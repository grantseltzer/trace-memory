#include "tracememory.skel.h"

static struct env {
	pid_t pid;
} env = {};

static const struct argp_option opts[] = {
    { "pid", 'p', "PID", 0, "Process ID to trace"},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    static int pos_args;
    long int pid;

    switch (key) {
        case 'p':
            errno = 0;
            pid = strtol(arg, NULL, 10);
            if (errno || pid <= 0) {
                fprintf(stderr, "INVALID PID: %s\n", arg);
            }
            env.pid = pid;
		    break;
    }
    return 0;
}

int libbpf_print_fn(enum libbpf_print_level level,
		    const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose) {
		return 0;
    }

	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct mmap_event *e = data;
    printf("%x %d\n", e.addr, e.length);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv) 
{
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
    };

    struct perf_buffer_opts pb_opts;
	struct perf_buffer *pb = NULL;
    struct tracememory_bpf *obj;
	int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        return err;
    }

    libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

    obj = tracememory_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	obj->rodata->target_tgid = env.pid;
    obj->rodata->targ_failed = env.failed;

    err = tracememory_bpf__load(obj);
    if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
    }

    err = tracememory_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

    pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;



cleanup:
	perf_buffer__free(pb);
	tracememory_bpf__destroy(obj);

}