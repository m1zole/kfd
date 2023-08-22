int get_kernel_rw(void);

uint64_t get_kbase(void);
uint64_t get_kslide(void);
uint64_t get_kernproc(void);
uint64_t get_allproc(void);

uint32_t kread32(uint64_t where);
uint64_t kread64(uint64_t where);
void kwrite32(uint64_t where, uint32_t what);
void kwrite64(uint64_t where, uint64_t what);
size_t kreadbuf(uint64_t kaddr, void *output, size_t size);
size_t kwritebuf(uint64_t kaddr, const void *input, size_t size);
void kwrite8(uint64_t where, uint8_t what);
void kwrite16(uint64_t where, uint16_t what);
uint8_t kread8(uint64_t where);
uint16_t kread16(uint64_t where);