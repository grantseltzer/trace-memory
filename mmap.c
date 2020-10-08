#include <linux/ptrace.h>
#include <openssl/sha.h>

enum events { MMAP, MUNMAP };

typedef struct mmap_args {
	u32 pid;
	int fd;
	void* addr;
	size_t length;
	int prot;
	int flags;
	off_t offset;
    unsigned long return_value;
} mmap_args_t;

BPF_HASH(mapped_region_cache, u64, mmap_args_t); // for saving mmap args in between enter and return
BPF_PERF_OUTPUT(output);

// WARNING: memory_regions should not be accessed directly!
BPF_HASH(memory_regions, u32, mmap_args_t);

void trace_mmap_enter(struct pt_regs *ctx) {

    // Only care about specific target process ID
    u64 pid = bpf_get_current_pid_tgid();
    if (pid != {{ .TargetPID }}) {
        return;
    }

    mmap_args_t args = {};
	args.pid = (u32)pid;
	
	// In kernel 4.17+ the actual context is stored by reference in di register
	struct pt_regs * actualCtx = (struct pt_regs *)ctx->di;
	bpf_probe_read(&args.addr, sizeof(args.addr), &actualCtx->di);
	bpf_probe_read(&args.length, sizeof(args.length), &actualCtx->si);
	bpf_probe_read(&args.prot, sizeof(args.prot), &actualCtx->dx);
	bpf_probe_read(&args.flags, sizeof(args.flags), &actualCtx->r10);
	bpf_probe_read(&args.fd, sizeof(args.fd), &actualCtx->r8);
	bpf_probe_read(&args.offset, sizeof(args.offset), &actualCtx->r9);

    byte in_memory_data[args.length];
    bpf_probe_read_kernel(&in_memory_data, args.length, &args.addr);

    char digest[SHA_DIGEST_LENGTH];
    SHA_CTX shactx;
    SHA1_Init(&shactx)
    SHA1_Update(&shactx, in_memory_data, DataLen);
    SHA1_Final(digest, &shactx);

    //TODO: Change ID to be a combination of the various fields
    u64 id;
    u32 tid;
    id = MMAP;
    tid = args.pid;
    id = id << 32 | tid;
    mapped_region_cache.update(&id, &args);
}

int trace_mmap_return(struct pt_regs *ctx) {

   // Only care about specific target process ID
    u64 pid = bpf_get_current_pid_tgid();
    if (pid != {{ .TargetPID }}) {
        return;
    }

    mmap_args_t *loaded_args;

    // determine id
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = MMAP;
    id = id << 32 | tid;

    loaded_args = mapped_region_cache.lookup(&id);
    if (loaded_args == 0) {
        return -1;
    }

    mapped_region_cache.delete(&id);
    loaded_args->return_value = PT_REGS_RC(ctx);

    bpf_trace_printk("%x\n", loaded_args->return_value);

    output.perf_submit(ctx, loaded_args, sizeof(mmap_args_t));  
    return 0;
}
