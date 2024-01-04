//
//  fun.c
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/07/25.
//

#include "krw.h"
#include "offsets.h"
#include <sys/stat.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <sys/mount.h>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/snapshot.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include "proc.h"
#include "vnode.h"
#include "grant_full_disk_access.h"
#include "thanks_opa334dev_htrowii.h"
#include "utils.h"

int do_fun(void) {
    
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
    funVnodeOverwrite2("/System/Library/Lockdown/iPhoneDebug.pem", [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/files/cert.pem"].UTF8String);

    return 0;
}
