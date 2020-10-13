// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
typedef struct mmap_args {
    void* addr;
    size_t length;
    int prot;
    int flags;
    int fd;
    off_t offset;
} mmap_args_t;