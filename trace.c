enum events { MMAP, MUNMAP };

typedef struct mapped_region {
    u32 pid;
    void* starting_addr;
    u32 length;
    u8 file_desc[]; 
    // Todo: mem prot/perm
} mapped_region_t;

// WARNING: memory_regions should not be accessed directly!
BPF_HASH(memory_regions, u32, mapped_region_t*)

int insert_mapped_region(u32 pid, mapped_region m) {
    mapped_region_t* regions = memory_regions.lookup(pid);
    
    // check starting addr and size of regions, scanning for where new one should go (can overlap)
    
    // if it would overlap in some way then combine into a current one, otherwise put in correct order

}

int remove_mapped_region(u32 pid, mapped_region m) {

}

int update_mapped_region(u32 pid, mapped_region m) {

}