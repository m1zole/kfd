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
#import "helpers.h"

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
    
    init_kcall();
    printf("[i] rootify ret: %d\n", rootify(getpid()));
    printf("[i] uid: %d, gid: %d\n", getuid(), getgid());

    prepare_kcall();
    
    platformize(getpid());
    
    uint64_t sb = unsandbox(getpid());
    
    //do some stuff here...
    loadTrustCacheBinpack();
    loadTrustCacheBinaries();
    
    term_kcall();   //After term_kcall called, kalloc/kfree/physrw NOT work.
//    goto TEMP_JUMP;
    
    cleanDropbearBootstrap();
//    runSSH(); //This would not be used anymore since have working JB.
    
    startJBEnvironment();   //oobPCI.swift -> case "startEnvironment":

//TEMP_JUMP:
//    test_launchdhook();
    
//    test_handoffKRW_jailbreakd();
//
//    test_communicate_jailbreakd();
    
    sandbox(getpid(), sb);
    
    //jb done, kclose and sbreload
    usleep(1000000);
    do_kclose();
    printf("Status: Done, sbreloading now...\n");
    usleep(3000000);
    restartBackboard();
    

    return 0;
}
