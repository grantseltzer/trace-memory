// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
typedef struct mmap_args {
   long addr;
    size_t length;
    int prot;
    int flags;
    int fd;
    off_t offset;
} mmap_args_t;

typedef struct mmap_event {
    u64 ts;
    u32 pid; 
    mmap_args_t args;
    //TODO: Add SHA1 of mem region
} mmap_event_t;
