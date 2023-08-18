//
//  krw.h
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/10.
//

#ifndef krw_h
#define krw_h

#include "fun.h"
#include <mach/mach.h>

typedef mach_port_t io_connect_t;
uint64_t IOConnectTrap6(io_connect_t, uint32_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

uint64_t do_kopen(uint64_t puaf_pages, uint64_t puaf_method, uint64_t kread_method, uint64_t kwrite_method);
void do_kclose(void);
void do_kread(uint64_t kaddr, void* uaddr, uint64_t size);
void do_kwrite(void* uaddr, uint64_t kaddr, uint64_t size);
uint64_t get_kslide(void);
uint64_t get_kernproc(void);
uint8_t kread8(uint64_t where);
uint32_t kread16(uint64_t where);
uint32_t kread32(uint64_t where);
uint64_t kread64(uint64_t where);
void kwrite8(uint64_t where, uint8_t what);
void kwrite16(uint64_t where, uint16_t what);
void kwrite32(uint64_t where, uint32_t what);
void kwrite64(uint64_t where, uint64_t what);
void kreadbuf(uint64_t kaddr, void* output, size_t size);

void init_kcall(void);
uint64_t kcall(uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6);
uint64_t dirty_kalloc(size_t size);

// used to fix what kexecute returns
typedef struct {
    uint64_t prev;
    uint64_t next;
    uint64_t start;
    uint64_t end;
} kmap_hdr_t;
uint64_t ZmFixAddr(uint64_t addr);

#endif /* krw_h */
