#include <argp.h>
#include <unistd.h>
#include "tracememory.skel.h"
#include "tracememory.h"

#define PERF_BUFFER_PAGES	64
#define PERF_BUFFER_TIME_MS	10
#define PERF_POLL_TIMEOUT_MS	100

static struct env {
	pid_t pid;
    bool verbose;
} env = {};

static const struct argp_option opts[] = {
    { "pid", 'p', "PID", 0, "Process ID to trace"},
    { "verbose", 'v', NULL, 0, "Verbose debug output" },
    {},
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
        case 'v':
		    env.verbose = true;
		    break;
        case ARGP_KEY_ARG:
            if (pos_args++) {
                fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
            }
            errno = 0;
            break;
        default:
            return 0;
    }
    return 0;
}

int libbpf_print_fn(enum libbpf_print_level level,
		    const char *format, va_list args)
{
	if (!env.verbose) {
		return 0;
    }
	return vfprintf(stderr, format, args);
}

void sprintMemoryProtectionFlag(int prot, char* protStr) {
    if (prot == 0x0) {
        sprintf(protStr, "%s", "NONE");
    }
    if ((prot&0x01) == 0x01) {
        strcat(protStr, "R");
    }
    if ((prot&0x02) == 0x02) {
        strcat(protStr, "W");
    }
    if ((prot&0x04) == 0x04) {
        strcat(protStr, "E");
    }
}

void sprintAddr(int addr, char* addrStr) {
    if (addr == 0) {
        sprintf(addrStr,"%s", "NULL");
        return;
    }
    sprintf(addrStr, "%x", addr);
    return;
}


void sprintMemoryVisibilityFlag(int vis, char* visStr) {

	if ((vis&0x01) == 0x01) {
		strcat(visStr, " MAP_SHARED");
	}

	if ((vis&0x02) == 0x02) {
		strcat(visStr, " MAP_PRIVATE");
	}
	
	if ((vis&0x02) == 0x03) {
		strcat(visStr, " MAP_SHARED_VALIDATE");
	}

	if ((vis&0x0f) == 0x10) {
		strcat(visStr, " MAP_ANONYMOUS");
	}

	if ((vis&0x0f) == 0x100) {
		strcat(visStr, " MAP_FIXED");
	}
		
	if ((vis&0x0f) == 0x40) {
		strcat(visStr, " MAP_32BIT");
	}
	
	if ((vis&0x0f) == 0x200000) {
		strcat(visStr, " MAP_FIXED_NOREPLACE");
	}

	if ((vis&0x0f) == 0x01000) {
		strcat(visStr, " MAP_GROWSDOWN");
	}

	if ((vis&0x0f) == 0x100000) {
		strcat(visStr, " MAP_HUGETLB");
	}		

	if ((vis&0x0f) == 0x08000) {
		strcat(visStr, " MAP_LOCKED");
	}

	if ((vis&0x0f) == 0x40000) {
		strcat(visStr, " MAP_NONBLOCK");
	}
	if ((vis&0x0f) == 0x20000) {
		strcat(visStr, " MAP_POPULATE");
	}
	if ((vis&0x0f) == 0x10000) {
		strcat(visStr, " MAP_NORESERVE");
	}
	if ((vis&0x0f) == 0x80000) {
		strcat(visStr, " MAP_STACK");
	}
	if ((vis&0x0f) == 0x4000000) {
		strcat(visStr, " MAP_UNINITIALIZED");
	}
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct mmap_event *e = data;
  
    char addr[12] = "";
    sprintAddr(e->args.addr, addr);
   
    char prot[20] = "";
    sprintMemoryProtectionFlag(e->args.prot, prot);

	char vis[50] = "";
	sprintMemoryVisibilityFlag(e->args.flags, vis);

    printf("PID: %d\tAddr: %s\tLen: %ld\tFD: %d\tProt: %s\tVisibility: %s\n", e->pid, addr, e->args.length, e->args.fd, prot, vis);
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

    obj = tracememory_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	obj->rodata->target_tgid = env.pid;

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

    pb = perf_buffer__new(bpf_map__fd(obj->maps.mmap_events), PERF_BUFFER_PAGES,
                    &pb_opts);
    err = libbpf_get_error(pb);
    if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

    while (1) {
        usleep(PERF_BUFFER_TIME_MS * 1000);
        if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0) {
			break;
        }
    }

    	printf("Error polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(pb);
	tracememory_bpf__destroy(obj);
}