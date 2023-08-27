//
//  stage2.h
//  kfd
//
//  Created by m1zole on 2023/08/25.
//

#ifndef stage2_h
#define stage2_h
uint64_t mineek_find_port(mach_port_name_t port);
uint64_t mineek_dirty_kalloc(size_t size);
void mineek_init_kcall(void);
uint64_t mineek_kcall(uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6);
void mineek_getRoot(uint64_t proc_addr);
void ucred_test(uint64_t proc_addr);
void stage2(void);
void stage2_all(void);

mach_port_t user_client;
uint64_t fake_vtable;
uint64_t fake_client;

#endif /* stage2_h */
