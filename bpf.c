// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

const struct event *_ __attribute__((unused));

struct config {
	__u64 xfrm_statistics;
};

static volatile const struct config CONFIG = {};

struct inc_ctx {
	__u8 register_idx;
};

struct bpf_map_def SEC("maps") inc_context = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct inc_ctx),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps") perf_output = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
};

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = 1<<29,
};

struct event {
	__u64 pc;
	__u64 skb;
	__u32 mark;
};

struct bpf_map_def SEC("maps") tid2skb = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct sk_buff *),
	.max_entries = 1<<16,
};

static __always_inline void read_reg(struct pt_regs *ctx, __u8 reg_idx, __u64 *reg)
{
	switch (reg_idx) {
	case 0:
		BPF_CORE_READ_INTO(reg, ctx, r15);
		break;
	case 1:
		BPF_CORE_READ_INTO(reg, ctx, r14);
		break;
	case 2:
		BPF_CORE_READ_INTO(reg, ctx, r13);
		break;
	case 3:
		BPF_CORE_READ_INTO(reg, ctx, r12);
		break;
	case 4:
		BPF_CORE_READ_INTO(reg, ctx, bp);
		break;
	case 5:
		BPF_CORE_READ_INTO(reg, ctx, bx);
		break;
	case 6:
		BPF_CORE_READ_INTO(reg, ctx, r11);
		break;
	case 7:
		BPF_CORE_READ_INTO(reg, ctx, r10);
		break;
	case 8:
		BPF_CORE_READ_INTO(reg, ctx, r9);
		break;
	case 9:
		BPF_CORE_READ_INTO(reg, ctx, r8);
		break;
	case 10:
		BPF_CORE_READ_INTO(reg, ctx, ax);
		break;
	case 11:
		BPF_CORE_READ_INTO(reg, ctx, cx);
		break;
	case 12:
		BPF_CORE_READ_INTO(reg, ctx, dx);
		break;
	case 13:
		BPF_CORE_READ_INTO(reg, ctx, si);
		break;
	case 14:
		BPF_CORE_READ_INTO(reg, ctx, di);
		break;
	case 15:
		BPF_CORE_READ_INTO(reg, ctx, orig_ax);
		break;
	case 16:
		BPF_CORE_READ_INTO(reg, ctx, ip);
		break;
	case 17:
		BPF_CORE_READ_INTO(reg, ctx, cs);
		break;
	case 18:
		BPF_CORE_READ_INTO(reg, ctx, flags);
		break;
	case 19:
		BPF_CORE_READ_INTO(reg, ctx, sp);
		break;
	case 20:
		BPF_CORE_READ_INTO(reg, ctx, ss);
		break;
	}
}

SEC("kprobe/ip_rcv")
int kprobe_ip_rcv(struct pt_regs *ctx)
{
	__u64 skb = (__u64)PT_REGS_PARM1(ctx);
	__u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
	bpf_map_update_elem(&tid2skb, &tid, &skb, BPF_ANY);
	return 0;
}

SEC("kretprobe/ip_rcv")
int kretprobe_ip_rcv(struct pt_regs *ctx)
{
	__u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
	bpf_map_delete_elem(&tid2skb, &tid);
	return 0;
}

SEC("kprobe/xfrm_inc_stats")
int kprobe_xfrm_inc_stats(struct pt_regs *ctx)
{
	__u64 pc = BPF_CORE_READ(ctx, ip)-1;
	struct inc_ctx *inc_ctx = bpf_map_lookup_elem(&inc_context, &pc);
	if (!inc_ctx) {
		bpf_printk("BUG: pc not found: %llx\n", pc);
		return 0;
	}

	__u64 reg = 1;
	read_reg(ctx, inc_ctx->register_idx, &reg);
	if (reg != CONFIG.xfrm_statistics) {
		return 0;
	}

	__u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
	struct sk_buff *skb = (struct sk_buff *)bpf_map_lookup_elem(&tid2skb, &tid);
	if (!skb) {
		bpf_printk("BUG: skb not found: %x\n", tid);
		return 0;
	}

	struct event ev = {};
	ev.pc = ctx->ip - 1;
	ev.skb = (__u64)skb;
	ev.mark = BPF_CORE_READ(skb, mark);
	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
	return 0;
}

SEC("kprobe/xfrm_statistics_seq_show")
int kprobe_xfrm_statistics_seq_show(struct pt_regs *ctx)
{
	struct seq_file *seq = (struct seq_file *)PT_REGS_PARM1(ctx);
	struct net *net = BPF_CORE_READ(seq, private);
	__u64 xfrm_statistics = (__u64)BPF_CORE_READ(net, mib.xfrm_statistics);
	bpf_perf_event_output(ctx, &perf_output, BPF_F_CURRENT_CPU, &xfrm_statistics, sizeof(xfrm_statistics));
	return 0;
}
