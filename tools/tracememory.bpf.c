#include "vmlinux.h"
#include "tracememory.h"
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct args_t);
} mmap_cache SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_mmap")
int tracepoint__syscalls__sys_enter_mmap(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	u32 pid = id;

    if (!trace_allowed(tgid, pid)) {
        return 1;
    }

    // store arg info for later lookup 
    mmap_args_t args = {};
    args.addr = (void*)ctx->args[0];
    args.length = (size_t)ctx->args[1];
    args.prot = (int)ctx->args[2];
    args.flags = (int)ctx->args[3];
    args.fd = (int)ctx->args[4];
    args.offset = (off_t)ctx->args[5];

    // TODO: Since this would likely trace a single PID
    //       change the ID in mmap cache to be a combination
    //       of these multiple fields (if accesible from the trace exit)
    //
    // TODO: What's the last argument?
    bpf_map_update_elem(&mmap_cache, &id, &args, 0); 

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int tracepoint__syscalls__sys_exit_mmap(struct trace_event_raw_sys_exit* ctx)
{
    
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int tracepoint__syscalls__sys_enter_munmap(struct trace_event_raw_sys_enter *ctx)
{
    
}
