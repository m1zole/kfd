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

uint64_t mountmobileDir(NSString* path) {
    NSString *mntPath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/mounted"];
    NSLog(@"%@", mntPath);
    
    uint64_t var_mobile_vnode = getVnodeAtPathByChdir((char *) [path UTF8String]);
    
    uint64_t orig_to_v_data = createFolderAndRedirect(var_mobile_vnode, mntPath);
    
    //UnRedirectAndRemoveFolder(orig_to_v_data, mntPath);
    
    return 0;
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

uint64_t mountAppsDir(void) {
    
    prepare();
    
    printf("[i] chown /var/containers/Bundle/Application\n");
    funVnodeChownFolder("/var/containers/Bundle/Application", 501, 501);
    
    printf("[i] mounting /var/containers/Bundle/Application\n");
    
    NSString *mntPath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/mounted"];
    
    uint64_t containers_vnode = getVnodeAtPathByChdir("/var/containers/Bundle/Application");
    printf("[i] /var/containers/Bundle/Application vnode: 0x%llx\n", containers_vnode);
    
    orig_to_v_data = createFolderAndRedirect(containers_vnode, mntPath);
    
    NSArray* dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mntPath error:NULL];
    NSLog(@"/var/containers/Bundle/Application directory list:\n %@", dirs);
    
    UnRedirectAndRemoveFolder(orig_to_v_data, mntPath);
    
    NSString *appstage1mntPath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/appstage1/"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:appstage1mntPath]) {
        [[NSFileManager defaultManager] createDirectoryAtPath:appstage1mntPath withIntermediateDirectories:YES attributes:nil error:nil];
    }
    NSString *appstage2mntPath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/appstage2/"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:appstage2mntPath]) {
        [[NSFileManager defaultManager] createDirectoryAtPath:appstage2mntPath withIntermediateDirectories:YES attributes:nil error:nil];
    }
    
    for(NSString *dir in dirs) {
        NSString *path = [NSString stringWithFormat:@"%s/%@", "/var/containers/Bundle/Application", dir];
        [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
        NSLog(@"full path:\n %@", path);
        //funVnodeChownFolder((char *) [path UTF8String], 501, 501);
        NSString *appmntPath = [NSString stringWithFormat:@"%@%@%@", NSHomeDirectory(), @"/Documents/appstage1/", dir];
        uint64_t containers_vnode = getVnodeAtPathByChdir((char *) [path UTF8String]);
        createFolderAndRedirect(containers_vnode, appmntPath);
        NSArray* targetdirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:appmntPath error:NULL];
        NSLog(@"appstage1 directory list: %@", targetdirs);
    }
    
    return 0;
}

void unmountAppsDir(uint64_t orig_to_v_data) {
    printf("[i] unmounting /var/containers/Bundle/Application\n");
    NSString *mntPath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/mounted"];
    UnRedirectAndRemoveFolder(orig_to_v_data, mntPath);
}

void containersdir(void) {
    if(orig_to_v_data == 0) {
        mountAppsDir();
    } else {
        unmountAppsDir(orig_to_v_data);
    }
}

void mountstage2(NSString* path) {
}
