#include "minimal_bpf.h"

#define MAX_FRAMES 32

struct raw_stack_entry {
    __u32 count;
    __u32 reserved;
    __u64 addrs[MAX_FRAMES];
};

struct tracer_stats {
    __u64 hits;
    __u64 captured;
    __u32 last_tgid;
    __u32 last_count;
    __s64 last_stack_result;
    __s64 reserved;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct raw_stack_entry);
} crash_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tracer_stats);
} tracer_stats SEC(".maps");

SEC("kprobe/do_coredump")
int on_do_coredump(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 zero = 0;
    struct tracer_stats *stats = bpf_map_lookup_elem(&tracer_stats, &zero);
    struct raw_stack_entry entry = {};
    long bytes;

    if (stats) {
        stats->hits += 1;
        stats->last_tgid = tgid;
    }

    bytes = bpf_get_stack(ctx, entry.addrs, sizeof(entry.addrs), BPF_F_USER_STACK);
    if (stats)
        stats->last_stack_result = bytes;
    if (bytes <= 0) {
        if (stats)
            stats->last_count = 0;
        return 0;
    }

    entry.count = bytes / sizeof(__u64);
    if (entry.count > MAX_FRAMES)
        entry.count = MAX_FRAMES;

    if (stats) {
        stats->captured += 1;
        stats->last_count = entry.count;
    }

    bpf_map_update_elem(&crash_stacks, &tgid, &entry, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
