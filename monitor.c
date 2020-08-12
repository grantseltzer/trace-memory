#include <uapi/linux/ptrace.h>

typedef struct mmap_args {
	u32 pid;
	int fd;
	void* addr;
	size_t length;
	int prot;
	int flags;
	off_t offset;
    unsigned long return_value;
} args_t;

enum events {
    MMAP
};

BPF_HASH(mmap_args, u64, args_t); // for saving mmap args in between enter and return
BPF_PERF_OUTPUT(output);

int trace_mmap_enter(struct pt_regs *ctx) {

    u64 id;
    u32 tid;
    args_t args = {};

	args.pid = (u32)bpf_get_current_pid_tgid();
	
	// In kernel 4.17+ the actual context is stored by reference in di register
	struct pt_regs * actualCtx = (struct pt_regs *)ctx->di;
	bpf_probe_read(&args.addr, sizeof(args.addr), &actualCtx->di);
	bpf_probe_read(&args.length, sizeof(args.length), &actualCtx->si);
	bpf_probe_read(&args.prot, sizeof(args.prot), &actualCtx->dx);
	bpf_probe_read(&args.flags, sizeof(args.flags), &actualCtx->r10);
	bpf_probe_read(&args.fd, sizeof(args.fd), &actualCtx->r8);
	bpf_probe_read(&args.offset, sizeof(args.offset), &actualCtx->r9);

    id = MMAP;
    tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;
    mmap_args.update(&id, &args);

	return 0;
}

int trace_mmap_return(struct pt_regs *ctx) {

    args_t *loaded_args;

    // determine id
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = MMAP;
    id = id << 32 | tid;

    loaded_args = mmap_args.lookup(&id);
    if (loaded_args == 0) {
        return -1;
    }

    mmap_args.delete(&id)

    loaded_args->return_value = PT_REGS_RC(ctx);
	output.perf_submit(ctx, loaded_args, sizeof(args_t));
    
    return 0;
}
