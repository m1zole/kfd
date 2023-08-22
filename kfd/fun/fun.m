//
//  fun.m
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/10.
//

#import <Foundation/Foundation.h>
#import <spawn.h>
#import <sys/stat.h>
#import <pthread.h>
#import "krw.h"
#import "offsets.h"
#import "sandbox.h"
#import "trustcache.h"
#import "escalate.h"
#import "utils.h"
#import "fun.h"
#import "proc.h"
#import "vnode.h"
#import "dropbear.h"
#import "./common/KernelRwWrapper.h"
#import "bootstrap.h"
#import "boot_info.h"
#import "jailbreakd_test.h"

void test_kalloc_kfree(void) {
    size_t allocated_size = 0x1000;
    uint64_t allocated_kmem = kalloc(allocated_size);
    kwrite64(allocated_kmem, 0x4142434445464748);
    printf("[+] allocated_kmem: 0x%llx\n", allocated_kmem);
    HexDump(allocated_kmem, allocated_size);
    
    kfree(allocated_kmem, allocated_size);
}

void test_unsandbox(void) {
    char* _token = token_by_sandbox_extension_issue_file("com.apple.app-sandbox.read-write", "/", 0);
    printf("consume ret: %lld\n", sandbox_extension_consume(_token));
    char* _token2 = token_by_sandbox_extension_issue_file("com.apple.sandbox.executable", "/", 0);
    printf("token2: %s\n", _token2);
    printf("consume ret: %lld\n", sandbox_extension_consume(_token2));
}

void test_load_trustcache(void) {
    const char* path = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/unsignedhelloworld"].UTF8String;
    chmod(path, 0755);
    printf("unsigned binaries path: %s\n", path);
    
    NSString* tcpath = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/binaries.tc"];
    
    uint64_t trustCacheKaddr = staticTrustCacheUploadFileAtPath(tcpath, NULL);
    printf("trustCacheKaddr: 0x%llx\n", trustCacheKaddr);
    util_runCommand(path, NULL, NULL);
    trustCacheListRemove(trustCacheKaddr);
}

void test_load_trustcache2(void) {
    const char* path = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/tar"].UTF8String;
    chmod(path, 0755);
    printf("unsigned binaries path: %s\n", path);
    
    NSString* tcpath = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/binaries.tc"];
    
    uint64_t trustCacheKaddr = staticTrustCacheUploadFileAtPath(tcpath, NULL);
    printf("trustCacheKaddr: 0x%llx\n", trustCacheKaddr);
    util_runCommand(path, NULL, NULL);
    trustCacheListRemove(trustCacheKaddr);
}

void* test_run_testkernrw(void* arg) {
    const char* path = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/test-kernrw"].UTF8String;
    util_runCommand(path, NULL, NULL);
    return NULL;
}

void test_handoffKRW(void) {
    NSString* tcpath = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/binaries.tc"];
    uint64_t trustCacheKaddr = staticTrustCacheUploadFileAtPath(tcpath, NULL);
    printf("trustCacheKaddr: 0x%llx\n", trustCacheKaddr);
    
    const char* path = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/test-kernrw"].UTF8String;
    chmod(path, 0755);
    
    pthread_t thread;
    if (pthread_create(&thread, NULL, test_run_testkernrw, NULL) != 0) {
        perror("pthread_create failed");
        return;
    }
    usleep(10000);
    pid_t test_pid = pid_by_name("test-kernrw");
    handoffKernRw(test_pid, path);
}

void test_launchdhook(void) {
    launch("/var/jb/basebin/opainject", "1", "/var/jb/basebin/launchdhook.dylib", NULL, NULL, NULL, NULL, NULL);
}

void test_physrw(void) {
    //physread test
    uint64_t target_kaddr = off_empty_kdata_page + get_kslide();
    kwrite64(target_kaddr, 0x4142434445464748);
    
    uint64_t phys_addr = kvtophys(target_kaddr);
    printf("off_empty_kdata_page kerneladdr -> physaddr: 0x%llx\n", phys_addr);
    printf("physread64 test: 0x%llx\n", physread64(phys_addr));
    
    //Restore
    kwrite64(off_empty_kdata_page + get_kslide(), 0x0);
    
    //physwrite test
    physwrite64(phys_addr, 0x12345678CAFEBABE);
    printf("physread64 test: 0x%llx\n", physread64(phys_addr));
    printf("kread64 test: 0x%llx\n", kread64(target_kaddr));
    //Restore again
    physwrite64(phys_addr, 0x0);
}

int do_fun(void) {
    printf("do_fun start!\n");
    usleep(1000000);

    uint64_t kslide = get_kslide();
    uint64_t kbase = 0xfffffff007004000 + kslide;
    
    printf("[i] Kernel base: 0x%llx\n", kbase);
    printf("[i] Kernel slide: 0x%llx\n", kslide);
    printf("[i] Kernel base kread64 ret: 0x%llx\n", kread64(kbase));
    
    printf("[i] rootify ret: %d\n", rootify(getpid()));
    printf("[i] uid: %d, gid: %d\n", getuid(), getgid());

    prepare_kcall();
    
    platformize(getpid());
    
    uint64_t sb = unsandbox(getpid());
    
    //do some stuff here...
    loadTrustCache();
    test_physrw();
    term_kcall();   //Since term_kcall called, kalloc/kfree NOT work.
    
    extractBootstrap();
    runSSH();
    
//    test_handoffKRW();
    
//    test_launchdhook();
    
    test_handoffKRW_jailbreakd();
    
    test_communicate_jailbreakd();
    
    sandbox(getpid(), sb);

    return 0;
}
