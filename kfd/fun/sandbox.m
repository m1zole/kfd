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
#import "boot_info.h"

uint64_t unsandbox(pid_t pid) {
    printf("[*] Unsandboxing pid %d\n", pid);
    
    if(off_p_ucred != 0){
        uint64_t proc = self_ro; // pid's proccess structure on the kernel
        uint64_t ucred =  get_ucred(proc); // pid credentials
        uint64_t cr_label = kread64(ucred + off_u_cr_label); // MAC label
        uint64_t orig_sb = kread64(cr_label + off_sandbox_slot);// not working
        kwrite64(cr_label + off_sandbox_slot /* First slot is AMFI's. so, this is second? */, 0); //get rid of sandbox by nullifying it
        return (kread64(kread64(ucred + off_u_cr_label) + off_sandbox_slot) == 0) ? orig_sb : NO;
    }
    usleep(1000);
    kcall(0xfffffff0077f5b50 + get_kslide(), cr_label + off_sandbox_slot, 0, 0, 0, 0, 0, 0);
    printf("[DEBUG] 0x%llx\n", kread64(kread64(self_ucred + off_u_cr_label) + off_sandbox_slot));
    return (kread64(kread64(self_ucred + off_u_cr_label) + off_sandbox_slot) == 0) ? orig_sb : NO;
}

BOOL sandbox(pid_t pid, uint64_t sb) {
    if (!pid) return NO;
    
    printf("[*] Sandboxing pid %d with slot at 0x%llx\n", pid, sb);
    if(off_p_ucred != 0){
        uint64_t proc = proc_of_pid(pid); // pid's proccess structure on the kernel
        uint64_t ucred = get_ucred(proc); // pid credentials
        uint64_t cr_label = kread64(ucred + off_u_cr_label); /* MAC label */
        kwrite64(cr_label + off_sandbox_slot /* First slot is AMFI's. so, this is second? */, sb);
        return (kread64(kread64(ucred + off_u_cr_label) + off_sandbox_slot) == sb) ? YES : NO;
    } else {
        kcall(off_mac_label_set + get_kslide(), cr_label + off_sandbox_slot, 0, 0, 0, 0, 0, 0);
        return (kread64(kread64(self_ucred + off_u_cr_label) + off_sandbox_slot) == 0) ? orig_sb : NO;
    }
}

char* token_by_sandbox_extension_issue_file(const char *extension_class, const char *path, uint32_t flags) {
    uint64_t self_ucreds = borrow_ucreds(getpid(), 1);
    char *ret = sandbox_extension_issue_file(extension_class, path, flags);
    unborrow_ucreds(getpid(), self_ucreds);
    
    return ret;
}

char *generateSystemWideSandboxExtensions(void) {
    uint64_t self_ucreds = borrow_ucreds(getpid(), 1);
    
  NSMutableString *extensionString = [NSMutableString new];

  // Make /var/jb readable
  [extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_file("com.apple.app-sandbox.read", prebootPath(nil).fileSystemRepresentation, 0)]];
  [extensionString appendString:@"|"];

  // Make binaries in /var/jb executable
    [extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_file("com.apple.sandbox.executable", prebootPath(nil).fileSystemRepresentation, 0)]];
  [extensionString appendString:@"|"];

  // Ensure the whole system has access to kr.h4ck.jailbreakd.systemwide
  [extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_mach("com.apple.app-sandbox.mach", "kr.h4ck.jailbreakd.systemwide", 0)]];
  [extensionString appendString:@"|"];
  [extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_mach("com.apple.security.exception." "mach-lookup.global-name", "kr.h4ck.jailbreakd.systemwide", 0)]];
    unborrow_ucreds(getpid(), self_ucreds);

  return extensionString.UTF8String;
}

void unsandbox_rootless(char* extensions) {
  char extensionsCopy[strlen(extensions)];
  strcpy(extensionsCopy, extensions);
  char *extensionToken = strtok(extensionsCopy, "|");
  while (extensionToken != NULL) {
    sandbox_extension_consume(extensionToken);
    extensionToken = strtok(NULL, "|");
  }
}
