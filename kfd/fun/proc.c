//
//  proc.c
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/19.
//

#include "proc.h"
#include "krw.h"
#include "offsets.h"

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

uint64_t proc_get_task(uint64_t proc) {
    return kread64(proc + off_p_task);
}

uint64_t task_get_vm_map(uint64_t task) {
    return kread64(task + off_task_map);
}

uint64_t vm_map_get_pmap(uint64_t vm_map) {
    return kread64(vm_map + off_vm_map_pmap);
}

uint64_t pmap_get_ttep(uint64_t pmap) {
    return kread64(pmap + off_pmap_ttep);
}

uint64_t get_ucred(uint64_t proc) {
    uint64_t ucred = 0;
    if(off_p_ucred == 0){
        uint64_t self_ro = kread64(proc + 0x20);
        printf("[DEBUG] self ro: 0x%llx\n", self_ro);
        uint64_t self_ucred = kread64(self_ro + 0x20);
        printf("[DEBUG] self ucred: 0x%llx\n", self_ucred); //ucred
        uint64_t kernproc = get_kernproc();
        printf("[DEBUG] Kernel proc: 0x%llx\n", kernproc);
        uint64_t kern_ro = kread64(kernproc + 0x20);
        printf("[DEBUG] Kernel ro: 0x%llx\n", kern_ro);
        uint64_t kern_ucred = kread64(kern_ro + 0x20);
        printf("[DEBUG] Kernel ucred: 0x%llx\n", kern_ucred); //kern_ucred
        uint64_t proc_set_ucred = off_proc_set_ucred;
        proc_set_ucred += get_kslide(); //proc_set_ucred
        printf("[DEBUG] Kernel set_ucred: 0x%llx\n", proc_set_ucred); //func:
        ucred = self_ucred;
        
    } else {
        ucred = kread64(proc + off_p_ucred);
    }
    return ucred;
}
