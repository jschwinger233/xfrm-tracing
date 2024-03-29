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
	__u64 ts;
	__u64 skb;
	__u32 len;
	__u32 mark;
	__u32 netns;
	__u32 ifindex;
	__u16 protocol;
	__u8 payload[64];

	__u32 xfrm_inc_stack_id;
};

struct inc_event {
	__u64 pc;
	__u32 xfrm_inc_stack_id;
};

struct bpf_map_def SEC("maps") tid2inc_event = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct inc_event),
	.max_entries = 1<<16,
};

struct bpf_map_def SEC("maps") stacks = {
	.type = BPF_MAP_TYPE_STACK_TRACE,
	.key_size = sizeof(__u32),
	.value_size = 50 * sizeof(__u64),
	.max_entries = 1<<8,
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

static __always_inline u32
get_netns(struct sk_buff *skb) {
	u32 netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);

	// if skb->dev is not initialized, try to get ns from sk->__sk_common.skc_net.net->ns.inum
	if (netns == 0)	{
		struct sock *sk = BPF_CORE_READ(skb, sk);
		if (sk != NULL)	{
			netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
		}
	}

	return netns;
}

SEC("kprobe/kfree_skbmem")
int kprobe_kfree_skbmem(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

	struct event ev = {};
	ev.pc = BPF_CORE_READ(ctx, ip)-1;
	ev.skb = (__u64)skb;

	__u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
	struct inc_event *inc_ev = bpf_map_lookup_elem(&tid2inc_event, &tid);
	if (!inc_ev) {
		bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
		return 0;
	}

	ev.pc = inc_ev->pc;
	ev.ts = bpf_ktime_get_boot_ns();
	ev.len = BPF_CORE_READ(skb, len);
	ev.mark = BPF_CORE_READ(skb, mark);
	ev.netns = get_netns(skb);
	ev.ifindex = BPF_CORE_READ(skb, dev, ifindex);
	ev.protocol = BPF_CORE_READ(skb, protocol);
	ev.mark = BPF_CORE_READ(skb, mark);
	ev.xfrm_inc_stack_id = inc_ev->xfrm_inc_stack_id;

	void *skb_head = BPF_CORE_READ(skb, head);
	u16 l3_off = BPF_CORE_READ(skb, network_header);
	bpf_probe_read_kernel(&ev.payload, sizeof(ev.payload), (void *)(skb_head + l3_off));
	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
	return 0;
}

SEC("kretprobe/kfree_skbmem")
int kretprobe_kfree_skbmem(struct pt_regs *ctx)
{
	__u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
	bpf_map_delete_elem(&tid2inc_event, &tid);
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

	struct inc_event inc_ev = {};
	inc_ev.pc = BPF_CORE_READ(ctx, ip) - 1;
	inc_ev.xfrm_inc_stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_FAST_STACK_CMP);

	__u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
	bpf_map_update_elem(&tid2inc_event, &tid, &inc_ev, BPF_ANY);
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

static __always_inline int
handle_everything(struct sk_buff *skb, struct pt_regs *ctx) {
	struct event ev = {};
	ev.pc = BPF_CORE_READ(ctx, ip)-1;
	ev.ts = bpf_ktime_get_boot_ns();
	ev.skb = (__u64)skb;
	ev.len = BPF_CORE_READ(skb, len);
	ev.mark = BPF_CORE_READ(skb, mark);
	ev.netns = get_netns(skb);
	ev.ifindex = BPF_CORE_READ(skb, dev, ifindex);
	ev.protocol = BPF_CORE_READ(skb, protocol);

	void *skb_head = BPF_CORE_READ(skb, head);
	u16 l3_off = BPF_CORE_READ(skb, network_header);
	bpf_probe_read_kernel(&ev.payload, sizeof(ev.payload), (void *)(skb_head + l3_off));
	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
	return 0;
}

#define PWRU_ADD_KPROBE(X)                                                     \
  SEC("kprobe/skb-" #X)                                             \
  int kprobe_skb_##X(struct pt_regs *ctx) {                                    \
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM##X(ctx);             \
    return handle_everything(skb, ctx);                  \
  }

PWRU_ADD_KPROBE(1)
PWRU_ADD_KPROBE(2)
PWRU_ADD_KPROBE(3)
PWRU_ADD_KPROBE(4)
PWRU_ADD_KPROBE(5)
