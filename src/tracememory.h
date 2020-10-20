struct mmap_args_t {
    long addr;
    size_t length;
    int prot;
    int flags;
    int fd;
    off_t offset;
};

struct mmap_event {
    __u64 ts;
    __u32 pid; 
    struct mmap_args_t args;
    //TODO: Add SHA1 of mem region
};

struct open_args_t {
    
};
