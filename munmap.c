#include <uapi/linux/ptrace.h>

typedef struct munmap_args {
    u32 pid;
    void* addr;
    size_t length;
    unsigned long return_value;
} munmap_args_t;

int trace_munmap_enter(struct pt_regs *ctx) {

    u64 id;
    u32 tid;
    munmap_args_t args = {};

    args.pid = (u32)bpf_get_current_pid_tgid();

	// In kernel 4.17+ the actual context is stored by reference in di register
    struct pt_regs * actualCtx = (struct pt_regs *)ctx->di;
	bpf_probe_read(&args.addr, sizeof(args.addr), &actualCtx->di);
	bpf_probe_read(&args.length, sizeof(args.length), &actualCtx->si);

    id = MUNMAP;
    tid = bpf_get_Current_pid_tgid();
    id = id << 32 | tid;
    mmap_args.update(&id, &args);

    return 0;
}


int trace_munmap_return(struct pt_regs *ctx) {

    munmap_args_t *loaded_args;

    // determine id
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = MUNMAP;
    id = id << 32 | tid;

    loaded_args = mmap_args.lookup(&id);
    if (loaded_args == 0) {
        return -1;
    }

    mmap_args.delete(&id)

    loaded_args->return_value = PT_REGS_RC(ctx);
	output.perf_submit(ctx, loaded_args, sizeof(mmap_args_t));
    
    return 0;
}