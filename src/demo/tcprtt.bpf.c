// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcprtt.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_established, struct sock *sk, struct sk_buff *skb)
{
	struct  ipv4_data_t *ipv4_data;
	pid_t pid;
	u32 srtt_us, srtt;
	struct sock_common  __sk_common;
	struct tcp_sock *ts = (struct tcp_sock *)sk;
	const struct inet_sock *inet = (struct inet_sock *)sk;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_probe_read_kernel(&srtt_us, sizeof(srtt_us), (void *)&ts->srtt_us);
    srtt = srtt_us >> 3;
    u16 sport = 0;
    u16 dport = 0;
    u32 saddr = 0;
	u32 daddr = 0;

	/* reserve sample from BPF ringbuf */
	ipv4_data = bpf_ringbuf_reserve(&rb, sizeof(*ipv4_data), 0);
	if (!ipv4_data)
		return 0;
	bpf_probe_read_kernel(&sport, sizeof(sport), (void *)&inet->inet_sport);
//	bpf_probe_read_kernel(&dport, sizeof(dport), (void *)&inet->inet_dport);
	bpf_probe_read_kernel(&__sk_common, sizeof(__sk_common), (void *)&sk->__sk_common);
	dport = __sk_common.skc_dport;
	bpf_probe_read_kernel(&saddr, sizeof(saddr), (void *)&inet->inet_saddr);
//	bpf_probe_read_kernel(&daddr, sizeof(daddr), (void *)&inet->inet_daddr);
	daddr = __sk_common.skc_daddr;

	ipv4_data->pid = pid;
	ipv4_data->saddr = saddr;
	ipv4_data->daddr = daddr;
	ipv4_data->sport = sport;
	ipv4_data->dport = dport;
	ipv4_data->srtt_ms = srtt / 1000;
	
	/* successfully submit it to user-space for post-processing */
    bpf_ringbuf_submit(ipv4_data, 0);

	return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(tcp_close, struct sock *sk)
{
	struct tcp_sock *ts = (struct tcp_sock *)sk;
	u32 srtt_us, srtt;
	bpf_probe_read_kernel(&srtt_us, sizeof(srtt_us), (void *)&ts->srtt_us);
	srtt = srtt_us >> 3;
	bpf_printk("tcp_close srtt is %llu\n", srtt);
	return 0;

}
