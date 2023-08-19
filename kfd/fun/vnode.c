//
//  vnode.c
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/19.
//

#include "vnode.h"
#include "krw.h"
#include "offsets.h"
#include "proc.h"

uint64_t findRootVnode(void) {
    uint64_t launchd_proc = proc_of_pid(1);
    
    uint64_t textvp_pac = kread64(launchd_proc + off_p_textvp);
    uint64_t textvp = textvp_pac;
    printf("[i] launchd proc->textvp: 0x%llx\n", textvp);

    uint64_t textvp_nameptr = kread64(textvp + off_vnode_v_name);
    uint64_t textvp_name = kread64(textvp_nameptr);
    printf("[i] launchd proc->textvp->v_name: %s\n", &textvp_name);
    
    uint64_t sbin_vnode = kread64(textvp + off_vnode_v_parent);
    textvp_nameptr = kread64(sbin_vnode + off_vnode_v_name);
    textvp_name = kread64(textvp_nameptr);
    printf("[i] launchd proc->textvp->v_parent->v_name: %s\n", &textvp_name);
    
    uint64_t root_vnode = kread64(sbin_vnode + off_vnode_v_parent);
    textvp_nameptr = kread64(root_vnode + off_vnode_v_name);
    textvp_name = kread64(textvp_nameptr);
    printf("[i] launchd proc->textvp->v_parent->v_parent->v_name: %s\n", &textvp_name);
    printf("[+] rootvnode: 0x%llx\n", root_vnode);
    
    return root_vnode;
}
