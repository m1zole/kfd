//
//  KFD-manager.m
//  kfd
//
//  Created by m1zole on 2023/09/16.
//

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include "../fun/vnode.h"
#include "../fun/utils.h"
#include "../fun/offsets.h"
#include "../fun/krw.h"
#include "../fun/proc.h"
#include "../fun/cs_blobs.h"
#include "../fun/fun.h"
#include "../fun/grant_full_disk_access.h"

uint64_t orig_to_v_data = 0;

uint64_t onlyFolderRedirect(uint64_t vnode, NSString *mntPath) {
    orig_to_v_data = funVnodeRedirectFolderFromVnode(mntPath.UTF8String, vnode);
    return orig_to_v_data;
}

uint64_t onlyUnRedirectFolder(uint64_t orig_to_v_data, NSString *mntPath) {
    funVnodeUnRedirectFolder(mntPath.UTF8String, orig_to_v_data);
    return 0;
}

void prepare(void) {
    _offsets_init();
    
    uint64_t kslide = get_kslide();
    uint64_t kbase = 0xfffffff007004000 + kslide;
    printf("[i] Kernel base: 0x%llx\n", kbase);
    printf("[i] Kernel slide: 0x%llx\n", kslide);
    uint64_t kheader64 = kread64(kbase);
    printf("[i] Kernel base kread64 ret: 0x%llx\n", kheader64);
    
    pid_t myPid = getpid();
    uint64_t selfProc = getProc(myPid);
    printf("[i] self proc: 0x%llx\n", selfProc);
    
    funUcred(selfProc);
    funProc(selfProc);
    printf("[i] pid: %d\n", getpid());
    funCSFlags("launchd");
    printf("[i] pid: %d\n", getpid());
    //funTask("kfd");
    mach_port_t host_self = mach_host_self();
    printf("[i] mach_host_self: 0x%x\n", host_self);
    fun_ipc_entry_lookup(host_self);
    
    //kfd_patch_installd();
    //kfd_grant_full_disk_access(^(NSError* error) {
    //    NSLog(@"[-] grant_full_disk_access returned error: %@", error);
    //});
}

uint64_t mountselectedDir(NSString* path) {
    NSString *mntPath = [NSString stringWithFormat:@"%@%@%@", NSHomeDirectory(), @"/Documents", path];
    NSLog(@"%@", mntPath);
    NSLog(@"%@", path);
    
    uint64_t vnode = getVnodeAtPathByChdir((char *) [path UTF8String]);
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:mntPath]) {
        printf("createFolderAndRedirect\n");
        orig_to_v_data = createFolderAndRedirect(vnode, mntPath);
    } else {
        printf("onlyFolderAndRedirect\n");
        orig_to_v_data = onlyFolderRedirect(vnode, mntPath);
    }
    printf("[i] orig_to_v_data: %llx", orig_to_v_data);
    return orig_to_v_data;
}

uint64_t mountusrDir(void) {
    
    printf("[i] mounting /usr\n");
    
    NSString *mntPath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/mounted"];
    
    uint64_t libexec_vnode = getVnodeAtPathByChdir("/usr");
    printf("[i] /usr vnode: 0x%llx\n", libexec_vnode);
    
    orig_to_v_data = createFolderAndRedirect(libexec_vnode, mntPath);
    
    NSArray* dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mntPath error:NULL];
    NSLog(@"/usr directory list:\n %@", dirs);
    
    UnRedirectAndRemoveFolder(orig_to_v_data, mntPath);
    
    return 0;
}

void unmountselectedDir(uint64_t orig_to_v_data, NSString* mntPath) {
    printf("[i] orig_to_v_data: %llx", orig_to_v_data);
    onlyUnRedirectFolder(orig_to_v_data, mntPath);
}

void mountstage2(NSString* path) {
}
