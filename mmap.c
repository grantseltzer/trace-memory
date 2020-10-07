#include <linux/ptrace.h>

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
    struct mmap_args* next;
} mmap_args_t;

BPF_HASH(mapped_region_cache, u64, mmap_args_t); // for saving mmap args in between enter and return
BPF_PERF_OUTPUT(output);

// WARNING: memory_regions should not be accessed directly!
BPF_HASH(memory_regions, u32, mmap_args_t);

static __always_inline void insert_mapped_region(u32 pid, mmap_args_t* m) {

    mmap_args_t *mem_list_head = memory_regions.lookup(&pid);

    if (!mem_list_head) {
        // PID's regions are not known about, insert head of list
        memory_regions.insert(&pid, m);
    }

    char inserted = 0;
    while (mem_list_head->next) {

        if (m->addr < mem_list_head->next->addr) {
            m->next = mem_list_head->next;
            mem_list_head->next = m;
            inserted = 1;
            break;
        } else {
            mem_list_head = mem_list_head->next;
        }
    }

    if (inserted == 0) {
        mem_list_head->next = m;
    }
}   

void trace_mmap_enter(struct pt_regs *ctx) {

    u64 id;
    u32 tid;
    mmap_args_t args = {};

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
    mapped_region_cache.update(&id, &args);
}

int trace_mmap_return(struct pt_regs *ctx) {

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

    //TODO: instead of perf_submit, call `insert_mapped_region`
    insert_mapped_region(tid, loaded_args);
	output.perf_submit(ctx, loaded_args, sizeof(mmap_args_t));
    
    return 0;
}


