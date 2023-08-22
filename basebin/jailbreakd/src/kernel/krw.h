#import <mach/mach.h>
#import <Foundation/Foundation.h>

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

int init_kcall(void);
int term_kcall(void);
uint64_t kcall(uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2,
               uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6);

uint64_t kalloc(size_t ksize);
void kfree(uint64_t kaddr, size_t ksize);


#ifdef __cplusplus
extern "C" {
#endif

typedef mach_port_t io_connect_t;
typedef mach_port_t io_service_t;
uint64_t IOConnectTrap6(io_connect_t, uint32_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
kern_return_t IOServiceOpen(io_service_t service, task_port_t owningTask, uint32_t type,io_connect_t *connect);
io_service_t IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching);
CFMutableDictionaryRef IOServiceMatching(const char *name);
extern const mach_port_t kIOMasterPortDefault;
#define IO_OBJECT_NULL 0

#ifdef __cplusplus
}
#endif