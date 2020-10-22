#include "vmlinux.h"
#include <bpf/bpf_helpers.h>       
#include "tracememory.h"
#include <sha3_helpers.h>

char LICENSE[] SEC("license") = "GPL";

const volatile pid_t target_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, struct mmap_args_t);
} mmap_cache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} mmap_events SEC(".maps");

static __always_inline
bool trace_allowed(u32 tgid)
{
	if (target_tgid && target_tgid != tgid) {
		return false;
    }
	return true;
}


SEC("tracepoint/syscalls/sys_enter_mmap")
int tracepoint__syscalls__sys_enter_mmap(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;

    if (!trace_allowed(tgid)) {
        return 1;
    }

    // store arg info for later lookup 
    struct mmap_args_t args = {};
    args.addr = (long)ctx->args[0];
    args.length = (size_t)ctx->args[1];
    args.prot = (int)ctx->args[2];
    args.flags = (int)ctx->args[3];
    args.fd = (int)ctx->args[4];
    args.offset = (off_t)ctx->args[5];

    sha3_context c;
    uint8_t *hash;

    sha3_Init256(&c);
    sha3_Update(&c, &args.addr, args.length);
    hash = (uint8_t*)sha3_Finalize(&c);
    bpf_trace_printk("%u\n", *hash);

   return bpf_map_update_elem(&mmap_cache, &id, &args, BPF_NOEXIST); 
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int tracepoint__syscalls__sys_exit_mmap(struct trace_event_raw_sys_exit* ctx)
{
    struct mmap_event event = {};
    struct mmap_args_t *args;
    int ret;
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    args = bpf_map_lookup_elem(&mmap_cache, &id);
    if (!args) {
        goto cleanup;
    }

    ret = ctx->ret;
    event.args = *args;
    event.pid = tgid;
    event.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &mmap_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

cleanup:
	bpf_map_delete_elem(&mmap_cache, &tgid);
	return 0;
}

