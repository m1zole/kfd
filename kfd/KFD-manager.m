//
//  KFD-manager.m
//  kfd
//
//  Created by m1zole on 2023/09/16.
//

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include "fun/vnode.h"
#include "fun/utils.h"
#include "fun/offsets.h"
#include "fun/krw.h"
#include "fun/proc.h"
#include "fun/cs_blobs.h"
#include "fun/fun.h"
#include "fun/grant_full_disk_access.h"
#include "fun/thanks_opa334dev_htrowii.h"
#include "kfd-Swift.h"

uint64_t orig_to_v_data = 0;

uint64_t onlyFolderRedirect(uint64_t vnode, NSString *mntPath) {
    orig_to_v_data = funVnodeRedirectFolderFromVnode(mntPath.UTF8String, vnode);
    return orig_to_v_data;
}

uint64_t onlyUnRedirectFolder(uint64_t orig_to_v_data, NSString *mntPath) {
    funVnodeUnRedirectFolder(mntPath.UTF8String, orig_to_v_data);
    return 0;
}

uint64_t do_getTask(char* process) {
    pid_t pid = getPidByName(process);
    uint64_t proc = getProc(pid);
    printf("[i] %s proc: 0x%llx\n", process, proc);
    uint64_t proc_ro = kread64(proc + off_p_proc_ro);
    
    /*
     * RO-protected flags:
     */
    #define TFRO_PLATFORM                   0x00000400                      /* task is a platform binary */
    #define TFRO_FILTER_MSG                 0x00004000                      /* task calls into message filter callback before sending a message */
    #define TFRO_PAC_EXC_FATAL              0x00010000                      /* task is marked a corpse if a PAC exception occurs */
    #define TFRO_PAC_ENFORCE_USER_STATE     0x01000000                      /* Enforce user and kernel signed thread state */
    
    uint32_t t_flags_ro = kread32(proc_ro + off_p_ro_t_flags_ro);
    printf("[i] %s proc->proc_ro->t_flags_ro: 0x%x\n", process, t_flags_ro);
    
    return 0;
}

void readtmplog(NSString* file) {
    NSString *mntPath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/mounted"];
    
    uint64_t var_tmp_vnode = getVnodeAtPathByChdir("/var/tmp");
    
    printf("[i] /var/tmp vnode: 0x%llx\n", var_tmp_vnode);
    
    uint64_t orig_to_v_data = createFolderAndRedirect(var_tmp_vnode, mntPath);
    
    NSError *error;

    printf("unredirecting from tmp\n");

    printf("reading log\n");
    
    NSLog(@"%@%@%@", NSHomeDirectory(), @"/Documents/mounted/", file);
    NSString *log = [NSString stringWithContentsOfFile:[NSString stringWithFormat:@"%@%@%@", NSHomeDirectory(), @"/Documents/mounted/", file] encoding:NSUTF8StringEncoding error:&error];
    NSLog(@"%@", log);
    
    UnRedirectAndRemoveFolder(orig_to_v_data, mntPath);
}

void getappslist(void) {
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
    //fun_ipc_entry_lookup(host_self);
    
    //kfd_patch_installd();
    //kfd_grant_full_disk_access(^(NSError* error) {
    //    NSLog(@"[-] grant_full_disk_access returned error: %@", error);
    //});
}

uint64_t mountusrDir(void) {
    
    NSString *mntPath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/mounted"];
    
    uint64_t libexec_vnode = getVnodeAtPathByChdir("/var/containers/Bundle/Application/CF553F26-ED5C-44A5-8AE5-0C1267BFFA8C/Tips.app");
    printf("[i] folder vnode: 0x%llx\n", libexec_vnode);
    
    orig_to_v_data = createFolderAndRedirect(libexec_vnode, mntPath);
    
    NSArray* dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mntPath error:NULL];
    NSLog(@"Tips directory list:\n %@", dirs);
    
    //UnRedirectAndRemoveFolder(orig_to_v_data, mntPath);
    
    return orig_to_v_data;
}

void do_tasks(void) {
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
    //funCSFlags("kfd");
    //funTask("kfd");
    mach_port_t host_self = mach_host_self();
    printf("[i] mach_host_self: 0x%x\n", host_self);
    fun_ipc_entry_lookup(host_self);
    //fun_nvram_dump();
    //readtmplog(@"ps.log");
    usleep(1000);
    //getappslist();
    printf("[i] vnode: %llx\n", getVnodeAtPathByChdir("/var/containers/Bundle/Application/856A4230-C48C-4F6E-BAA4-E0BD1084AE6C/Books.app"));
    printf("[i] vnode: %llx\n", findChildVnodeByVnode(getVnodeAtPathByChdir("/var/containers/Bundle/Application/856A4230-C48C-4F6E-BAA4-E0BD1084AE6C/Books.app"), "Books.app"));
    printf("[i] vnode: %llx\n", findChildVnodeByVnode(getVnodeAtPathByChdir("/var/mobile"), "TCC.framework"));
    
    //funVnodeOverwriteFile("/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", "/Developer/System/Library/PrivateFrameworks/TCC.framework/Support/tccd_ori");
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

void unmountselectedDir(uint64_t orig_to_v_data, NSString* mntPath) {
    printf("[i] orig_to_v_data: %llx", orig_to_v_data);
    onlyUnRedirectFolder(orig_to_v_data, mntPath);
}

bool check_mdc(void) {
    if (@available(iOS 16.2, *)) {
        return true;
    } else {
        return false;
    }
}

