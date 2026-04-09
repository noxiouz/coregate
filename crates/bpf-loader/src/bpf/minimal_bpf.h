#ifndef __COREGATE_MINIMAL_BPF_H__
#define __COREGATE_MINIMAL_BPF_H__

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

struct pt_regs;

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static long (*bpf_get_stack)(void *ctx, void *buf, __u32 size, __u64 flags) = (void *) 67;

#endif
