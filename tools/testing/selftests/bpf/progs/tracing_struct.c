// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

struct bpf_testmod_struct_arg_1 {
	int a;
};
struct bpf_testmod_struct_arg_2 {
	long a;
	long b;
};

long t1_a_a, t1_a_b, t1_b, t1_c, t1_ret, t1_nregs;
__u64 t1_reg0, t1_reg1, t1_reg2, t1_reg3;
long t2_a, t2_b_a, t2_b_b, t2_c, t2_ret;
long t3_a, t3_b, t3_c_a, t3_c_b, t3_ret;
long t4_a_a, t4_b, t4_c, t4_d, t4_e_a, t4_e_b, t4_ret;
long t5_ret;

SEC("fentry/bpf_testmod_test_struct_arg_1")
int BPF_PROG2(test_struct_arg_1, struct bpf_testmod_struct_arg_2, a, int, b, int, c)
{
	t1_a_a = a.a;
	t1_a_b = a.b;
	t1_b = b;
	t1_c = c;
	return 0;
}

SEC("fexit/bpf_testmod_test_struct_arg_1")
int BPF_PROG2(test_struct_arg_2, struct bpf_testmod_struct_arg_2, a, int, b, int, c, int, ret)
{
	t1_nregs =  bpf_get_func_arg_cnt(ctx);
	/* a.a */
	bpf_get_func_arg(ctx, 0, &t1_reg0);
	/* a.b */
	bpf_get_func_arg(ctx, 1, &t1_reg1);
	/* b */
	bpf_get_func_arg(ctx, 2, &t1_reg2);
	t1_reg2 = (int)t1_reg2;
	/* c */
	bpf_get_func_arg(ctx, 3, &t1_reg3);
	t1_reg3 = (int)t1_reg3;

	t1_ret = ret;
	return 0;
}

SEC("fentry/bpf_testmod_test_struct_arg_2")
int BPF_PROG2(test_struct_arg_3, int, a, struct bpf_testmod_struct_arg_2, b, int, c)
{
	t2_a = a;
	t2_b_a = b.a;
	t2_b_b = b.b;
	t2_c = c;
	return 0;
}

SEC("fexit/bpf_testmod_test_struct_arg_2")
int BPF_PROG2(test_struct_arg_4, int, a, struct bpf_testmod_struct_arg_2, b, int, c, int, ret)
{
	t2_ret = ret;
	return 0;
}

SEC("fentry/bpf_testmod_test_struct_arg_3")
int BPF_PROG2(test_struct_arg_5, int, a, int, b, struct bpf_testmod_struct_arg_2, c)
{
	t3_a = a;
	t3_b = b;
	t3_c_a = c.a;
	t3_c_b = c.b;
	return 0;
}

SEC("fexit/bpf_testmod_test_struct_arg_3")
int BPF_PROG2(test_struct_arg_6, int, a, int, b, struct bpf_testmod_struct_arg_2, c, int, ret)
{
	t3_ret = ret;
	return 0;
}

SEC("fentry/bpf_testmod_test_struct_arg_4")
int BPF_PROG2(test_struct_arg_7, struct bpf_testmod_struct_arg_1, a, int, b,
	     int, c, int, d, struct bpf_testmod_struct_arg_2, e)
{
	t4_a_a = a.a;
	t4_b = b;
	t4_c = c;
	t4_d = d;
	t4_e_a = e.a;
	t4_e_b = e.b;
	return 0;
}

SEC("fexit/bpf_testmod_test_struct_arg_4")
int BPF_PROG2(test_struct_arg_8, struct bpf_testmod_struct_arg_1, a, int, b,
	     int, c, int, d, struct bpf_testmod_struct_arg_2, e, int, ret)
{
	t4_ret = ret;
	return 0;
}

SEC("fentry/bpf_testmod_test_struct_arg_5")
int BPF_PROG2(test_struct_arg_9)
{
	return 0;
}

SEC("fexit/bpf_testmod_test_struct_arg_5")
int BPF_PROG2(test_struct_arg_10, int, ret)
{
	t5_ret = ret;
	return 0;
}

char _license[] SEC("license") = "GPL";
