// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct config {
	__u64 xfrm_statistics;
};

static volatile const struct config CONFIG = {};

#define OFF_XFRM_MIB (offsetof(struct net, mib) + offsetof(struct netns_mib, xfrm_statistics))

struct bpf_map_def SEC("maps") saved_xfrm_mib = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u64),
	.max_entries = 29,
};

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

static __always_inline void read_reg(struct pt_regs *ctx, __u8 reg_idx, __u64 reg)
{
	switch (reg_idx) {
	case 0:
		BPF_CORE_READ_INTO(&reg, ctx, r15);
		break;
	case 1:
		BPF_CORE_READ_INTO(&reg, ctx, r14);
		break;
	case 2:
		BPF_CORE_READ_INTO(&reg, ctx, r13);
		break;
	case 3:
		BPF_CORE_READ_INTO(&reg, ctx, r12);
		break;
	case 4:
		BPF_CORE_READ_INTO(&reg, ctx, bp);
		break;
	case 5:
		BPF_CORE_READ_INTO(&reg, ctx, bx);
		break;
	case 6:
		BPF_CORE_READ_INTO(&reg, ctx, r11);
		break;
	case 7:
		BPF_CORE_READ_INTO(&reg, ctx, r10);
		break;
	case 8:
		BPF_CORE_READ_INTO(&reg, ctx, r9);
		break;
	case 9:
		BPF_CORE_READ_INTO(&reg, ctx, r8);
		break;
	case 10:
		BPF_CORE_READ_INTO(&reg, ctx, ax);
		break;
	case 11:
		BPF_CORE_READ_INTO(&reg, ctx, cx);
		break;
	case 12:
		BPF_CORE_READ_INTO(&reg, ctx, dx);
		break;
	case 13:
		BPF_CORE_READ_INTO(&reg, ctx, si);
		break;
	case 14:
		BPF_CORE_READ_INTO(&reg, ctx, di);
		break;
	case 15:
		BPF_CORE_READ_INTO(&reg, ctx, orig_ax);
		break;
	case 16:
		BPF_CORE_READ_INTO(&reg, ctx, ip);
		break;
	case 17:
		BPF_CORE_READ_INTO(&reg, ctx, cs);
		break;
	case 18:
		BPF_CORE_READ_INTO(&reg, ctx, flags);
		break;
	case 19:
		BPF_CORE_READ_INTO(&reg, ctx, sp);
		break;
	case 20:
		BPF_CORE_READ_INTO(&reg, ctx, ss);
		break;
	}
}

SEC("kprobe/xfrm_inc_stats")
int kprobe_xfrm_inc_stats(struct pt_regs *ctx)
{
	__u64 pc = BPF_CORE_READ(ctx, ip)-1;
	struct inc_ctx *inc_ctx = bpf_map_lookup_elem(&inc_context, &pc);
	if (!inc_ctx) {
		bpf_printk("pc not found: %llx\n", pc);
		return 0;
	}

	__u64 reg;
	read_reg(ctx, inc_ctx->register_idx, reg);
	if (reg != CONFIG.xfrm_statistics) {
		return 0;
	}

	bpf_printk("xfrm_inc_stats: %llx\n", ctx->ip);
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

SEC("kprobe/kfree_skbmem")
int kprobe_kfree_skbmem(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	struct net *net = BPF_CORE_READ(skb, dev, nd_net.net);
	__u64 _mib = (__u64)BPF_CORE_READ(skb, dev, nd_net.net, mib.xfrm_statistics);
	//__u64 _mib;
	//bpf_probe_read_kernel(&_mib, sizeof(_mib), (void *)net+0x1a8);



	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 fsbase = BPF_CORE_READ(task, thread.fsbase);
	__u64 gsbase = BPF_CORE_READ(task, thread.gsbase);
	if (_mib != 0)
		bpf_printk("%llx, mib = %llx, gsbase = %llx\n", OFF_XFRM_MIB, _mib, fsbase);
	struct linux_xfrm_mib *mib = (struct linux_xfrm_mib *)(gsbase + _mib);

	__u64 xfrm_stat;
	for (int idx=1; idx<29; idx++) {
		bpf_probe_read_kernel(&xfrm_stat, sizeof(xfrm_stat), &mib->mibs[idx]);

		int i = idx;
		__u64 *orig_xfrm_stat = (__u64 *)bpf_map_lookup_elem(&saved_xfrm_mib, &i);
		if (!orig_xfrm_stat)
			continue;

		//bpf_printk("xfrm_stat[%d] = %d(+%d)\n", OFF_XFRM_MIB, xfrm_stat, xfrm_stat - *orig_xfrm_stat);
		if (xfrm_stat > 0) {
			bpf_printk("xfrm_stat[%d] = %llu(+%d)\n", idx, xfrm_stat, xfrm_stat - *orig_xfrm_stat);
			i = idx;
			bpf_map_update_elem(&saved_xfrm_mib, &i, &xfrm_stat, BPF_ANY);
		}
	}
	return 0;
}

