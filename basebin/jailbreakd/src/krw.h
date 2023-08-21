#import <Foundation/Foundation.h>
#include <mach/vm_prot.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct __attribute__((__packed__)) _vm_map_flags {
    unsigned int
        /* boolean_t */ wait_for_space:1,         /* Should callers wait for space? */
        /* boolean_t */ wiring_required:1,        /* All memory wired? */
        /* boolean_t */ no_zero_fill:1,           /* No zero fill absent pages */
        /* boolean_t */ mapped_in_other_pmaps:1,  /* has this submap been mapped in maps that use a different pmap */
        /* boolean_t */ switch_protect:1,         /* Protect map from write faults while switched */
        /* boolean_t */ disable_vmentry_reuse:1,  /* All vm entries should keep using newer and higher addresses in the map */
        /* boolean_t */ map_disallow_data_exec:1, /* Disallow execution from data pages on exec-permissive architectures */
        /* boolean_t */ holelistenabled:1,
        /* boolean_t */ is_nested_map:1,
        /* boolean_t */ map_disallow_new_exec:1, /* Disallow new executable code */
        /* boolean_t */ jit_entry_exists:1,
        /* boolean_t */ has_corpse_footprint:1,
        /* boolean_t */ terminated:1,
        /* boolean_t */ is_alien:1,              /* for platform simulation, i.e. PLATFORM_IOS on OSX */
        /* boolean_t */ cs_enforcement:1,        /* code-signing enforcement */
        /* boolean_t */ cs_debugged:1,           /* code-signed but debugged */
        /* boolean_t */ reserved_regions:1,      /* has reserved regions. The map size that userspace sees should ignore these. */
        /* boolean_t */ single_jit:1,            /* only allow one JIT mapping */
        /* boolean_t */ never_faults : 1,        /* only seen in KDK */
        /* reserved */ pad:13;
} vm_map_flags;

void get_kernel_rw(void);

size_t kread(uint64_t addr, void *p, size_t size);

uint8_t kread8(uint64_t where);

uint32_t kread16(uint64_t where);
uint32_t kread32(uint64_t where);
uint64_t kread64(uint64_t where);

void kwrite32(uint64_t where, uint32_t what);
void kwrite64(uint64_t where, uint64_t what);

size_t kwrite(uint64_t where, const void *p, size_t size);

void kwrite8(uint64_t where, uint8_t what);

void kwrite16(uint64_t where, uint16_t what);

uint64_t self_proc(void);

uint64_t proc_of_pid(pid_t pid);

void run_unsandboxed(void (^block)(void));

uint64_t vm_map_get_header(uint64_t vm_map_ptr);

uint64_t vm_map_header_get_first_entry(uint64_t vm_header_ptr);

uint32_t vm_header_get_nentries(uint64_t vm_header_ptr);

void vm_entry_get_range(uint64_t vm_entry_ptr, uint64_t *start_address_out, uint64_t *end_address_out);
uint64_t vm_map_entry_get_next_entry(uint64_t vm_entry_ptr);

void vm_map_entry_get_prot(uint64_t entry_ptr, vm_prot_t *prot, vm_prot_t *max_prot);
void vm_map_entry_set_prot(uint64_t entry_ptr, vm_prot_t prot, vm_prot_t max_prot);

uint64_t proc_get_pptr(uint64_t proc_ptr);

uint64_t proc_get_task(uint64_t proc_ptr);

uint64_t task_get_vm_map(uint64_t task_ptr);

uint64_t vm_map_get_pmap(uint64_t vm_map_ptr);
void pmap_set_wx_allowed(uint64_t pmap_ptr, bool wx_allowed);

uint32_t proc_get_csflags(uint64_t proc);

void task_set_memory_ownership_transfer(uint64_t task_ptr, uint8_t enabled);

vm_map_flags vm_map_get_flags(uint64_t vm_map_ptr);

void vm_map_set_flags(uint64_t vm_map_ptr, vm_map_flags new_flags);

int proc_set_debugged(uint64_t proc_ptr, bool fully_debugged);

#ifdef __cplusplus
}
#endif
