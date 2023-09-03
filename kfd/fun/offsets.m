//
//  offsets.m
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/10.
//

#include "offsets.h"
#include <UIKit/UIKit.h>
#include <Foundation/Foundation.h>

uint32_t off_p_list_le_prev = 0;
uint32_t off_p_name = 0;
uint32_t off_p_pid = 0;
uint32_t off_p_ucred = 0;
uint32_t off_p_task = 0;
uint32_t off_p_csflags = 0;
uint32_t off_p_uid = 0;
uint32_t off_p_gid = 0;
uint32_t off_p_ruid = 0;
uint32_t off_p_rgid = 0;
uint32_t off_p_svuid = 0;
uint32_t off_p_svgid = 0;
uint32_t off_p_textvp = 0;
uint32_t off_p_pfd = 0;
uint32_t off_u_cr_label = 0;
uint32_t off_u_cr_uid = 0;
uint32_t off_u_cr_ruid = 0;
uint32_t off_u_cr_svuid = 0;
uint32_t off_u_cr_ngroups = 0;
uint32_t off_u_cr_groups = 0;
uint32_t off_u_cr_rgid = 0;
uint32_t off_u_cr_svgid = 0;
uint32_t off_task_t_flags = 0;
uint32_t off_task_itk_space = 0;
uint32_t off_task_map = 0;
uint32_t off_vm_map_pmap = 0;
uint32_t off_pmap_ttep = 0;
uint32_t off_vnode_v_name = 0;
uint32_t off_vnode_v_parent = 0;
uint32_t off_vnode_v_data = 0;
uint32_t off_fp_glob = 0;
uint32_t off_fg_data = 0;
uint32_t off_vnode_vu_ubcinfo = 0;
uint32_t off_ubc_info_cs_blobs = 0;
uint32_t off_cs_blob_csb_platform_binary = 0;
uint32_t off_ipc_port_ip_kobject = 0;
uint32_t off_ipc_space_is_table = 0;
uint32_t off_amfi_slot = 0;
uint32_t off_sandbox_slot = 0;


//kernel func
uint64_t off_kalloc_data_external = 0;
uint64_t off_kfree_data_external = 0;
uint64_t off_add_x0_x0_0x40_ret = 0;
uint64_t off_empty_kdata_page = 0;
uint64_t off_trustcache = 0;
uint64_t off_gphysbase = 0;
uint64_t off_gphyssize = 0;
uint64_t off_pmap_enter_options_addr = 0;
uint64_t off_allproc = 0;
uint64_t off_pmap_find_phys = 0;
uint64_t off_ml_phys_read_data = 0;
uint64_t off_ml_phys_write_data = 0;
uint64_t off_proc_set_ucred = 0;
uint64_t off_unknown = 0;
uint64_t off_mac_label_set = 0;
uint64_t off_proc_rele = 0;
uint64_t off_proc_find = 0;

#define SYSTEM_VERSION_EQUAL_TO(v)                  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)

void _offsets_init(void) {
    if (SYSTEM_VERSION_EQUAL_TO(@"15.0")) {
        printf("[i] offsets selected for iOS 15.0\n");
        //iPhone 6s 15.0 offsets
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/proc_internal.h#L227
        off_p_list_le_prev = 0x8;
        off_p_name = 0x2d9;
        off_p_pid = 0x68;
        off_p_ucred = 0;
        off_p_task = 0x10;
        off_p_csflags = 0x300;
        off_p_uid = 0x2c;
        off_p_gid = 0x30;
        off_p_ruid = 0x34;
        off_p_rgid = 0x38;
        off_p_svuid = 0x3c;
        off_p_svgid = 0x40;
        off_p_textvp = 0x2a8;
        off_p_pfd = 0x100;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ucred.h#L91
        off_u_cr_label = 0x78;
        off_u_cr_uid = 0x18;
        off_u_cr_ruid = 0x1c;
        off_u_cr_svuid = 0x20;
        off_u_cr_ngroups = 0x24;
        off_u_cr_groups = 0x28;
        off_u_cr_rgid = 0x68;
        off_u_cr_svgid = 0x6c;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/kern/task.h#L157
        off_task_t_flags = 0x3e8;
        off_task_itk_space = 0x330;
        off_task_map = 0x28;    //_get_task_pmap
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/vm/vm_map.h#L471
        off_vm_map_pmap = 0x48;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/arm/pmap.h#L377
        off_pmap_ttep = 0x8;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/vnode_internal.h#L142
        off_vnode_vu_ubcinfo = 0x78;
        off_vnode_v_name = 0xb8;
        off_vnode_v_parent = 0xc0;
        off_vnode_v_data = 0xe0;
        
        off_fp_glob = 0x10;
        
        off_fg_data = 0x38;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L149
        off_ubc_info_cs_blobs = 0x50;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L102
        off_cs_blob_csb_platform_binary = 0xb8;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_port.h#L152
        //https://github.com/0x7ff/dimentio/blob/7ffffffb4ebfcdbc46ab5e8f1becc0599a05711d/libdimentio.c#L958
        off_ipc_port_ip_kobject = 0x58;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_space.h#L128
        off_ipc_space_is_table = 0x20;
        
        off_amfi_slot = 0x8;
        off_sandbox_slot = 0x10;
        
        off_kalloc_data_external = 0xfffffff007188c4c;
        off_kfree_data_external = 0xfffffff007189458;
        //off_add_x0_x0_0x40_ret = 0xFFFFFFF005C2AEC0;
        off_empty_kdata_page = 0xfffffff0077e0000 + 0x100;
        off_trustcache = 0xfffffff007878880;
        off_gphysbase = 0xfffffff0070cba28; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d
        off_gphyssize = 0xfffffff0070cba48; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d
        off_pmap_enter_options_addr = 0xfffffff0072825f4;//vm_map_get_pmap
        off_allproc = 0xfffffff007853900;//find_allproc
        off_pmap_find_phys = 0xfffffff007288a54;
        off_ml_phys_read_data = 0xfffffff0072984f8;
        off_ml_phys_write_data = 0xfffffff00729877c;
        off_unknown = 0xfffffff007102498;
        
    } else if (SYSTEM_VERSION_EQUAL_TO(@"15.0.2")) {
        printf("[i] offsets selected for iOS 15.0.2\n");
        //iPhone 6s 15.0.2 offsets
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/proc_internal.h#L227
        off_p_list_le_prev = 0x8;
        off_p_name = 0x2d9;
        off_p_pid = 0x68;
        off_p_ucred = 0xd8;
        off_p_task = 0x10;
        off_p_csflags = 0x300;
        off_p_uid = 0x2c;
        off_p_gid = 0x30;
        off_p_ruid = 0x34;
        off_p_rgid = 0x38;
        off_p_svuid = 0x3c;
        off_p_svgid = 0x40;
        off_p_textvp = 0x2a8;
        off_p_pfd = 0x100;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ucred.h#L91
        off_u_cr_label = 0x78;
        off_u_cr_uid = 0x18;
        off_u_cr_ruid = 0x1c;
        off_u_cr_svuid = 0x20;
        off_u_cr_ngroups = 0x24;
        off_u_cr_groups = 0x28;
        off_u_cr_rgid = 0x68;
        off_u_cr_svgid = 0x6c;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/kern/task.h#L157
        off_task_t_flags = 0x3e8;
        off_task_itk_space = 0x330;
        off_task_map = 0x28;    //_get_task_pmap
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/vm/vm_map.h#L471
        off_vm_map_pmap = 0x48;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/arm/pmap.h#L377
        off_pmap_ttep = 0x8;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/vnode_internal.h#L142
        off_vnode_vu_ubcinfo = 0x78;
        off_vnode_v_name = 0xb8;
        off_vnode_v_parent = 0xc0;
        off_vnode_v_data = 0xe0;
        
        off_fp_glob = 0x10;
        
        off_fg_data = 0x38;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L149
        off_ubc_info_cs_blobs = 0x50;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L102
        off_cs_blob_csb_platform_binary = 0xb8;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_port.h#L152
        //https://github.com/0x7ff/dimentio/blob/7ffffffb4ebfcdbc46ab5e8f1becc0599a05711d/libdimentio.c#L958
        off_ipc_port_ip_kobject = 0x58;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_space.h#L128
        off_ipc_space_is_table = 0x20;
        
        off_amfi_slot = 0x8;
        off_sandbox_slot = 0x10;
        
        off_kalloc_data_external = 0xFFFFFFF007188C4C;
        off_kfree_data_external = 0xFFFFFFF007189458;
        off_add_x0_x0_0x40_ret = 0xFFFFFFF005C41EC0;
        off_empty_kdata_page = 0xFFFFFFF0077E0000 + 0x100;
        off_trustcache = 0xFFFFFFF007878880;
        off_gphysbase = 0xFFFFFFF0070CBA28; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d
        off_gphyssize = 0xFFFFFFF0070CBB20; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d
        off_pmap_enter_options_addr = 0xFFFFFFF0072825F4;
        off_allproc = 0xFFFFFFF007853900;
        off_pmap_find_phys = 0xFFFFFFF007288A54;
        off_ml_phys_read_data = 0xFFFFFFF0072984F8;
        off_ml_phys_write_data = 0xFFFFFFF00729877C;
        
    } else if (SYSTEM_VERSION_EQUAL_TO(@"15.1")) {
        printf("[i] offsets selected for iOS 15.1\n");
        //iPhone 8 15.1 offsets
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/proc_internal.h#L227
        off_p_list_le_prev = 0x8;
        off_p_name = 0x2d9;
        off_p_pid = 0x68;
        off_p_ucred = 0xd8;
        off_p_task = 0x10;
        off_p_csflags = 0x300;
        off_p_uid = 0x2c;
        off_p_gid = 0x30;
        off_p_ruid = 0x34;
        off_p_rgid = 0x38;
        off_p_svuid = 0x3c;
        off_p_svgid = 0x40;
        off_p_textvp = 0x2a8;
        off_p_pfd = 0x100;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ucred.h#L91
        off_u_cr_label = 0x78;
        off_u_cr_uid = 0x18;
        off_u_cr_ruid = 0x1c;
        off_u_cr_svuid = 0x20;
        off_u_cr_ngroups = 0x24;
        off_u_cr_groups = 0x28;
        off_u_cr_rgid = 0x68;
        off_u_cr_svgid = 0x6c;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/kern/task.h#L157
        off_task_t_flags = 0x3e8;
        off_task_itk_space = 0x330;
        off_task_map = 0x28;    //_get_task_pmap

        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/vm/vm_map.h#L471
        off_vm_map_pmap = 0x48;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/arm/pmap.h#L377
        off_pmap_ttep = 0x8;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/vnode_internal.h#L142
        off_vnode_vu_ubcinfo = 0x78;
        off_vnode_v_name = 0xb8;
        off_vnode_v_parent = 0xc0;
        off_vnode_v_data = 0xe0;
        
        off_fp_glob = 0x10;
        
        off_fg_data = 0x38;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L149
        off_ubc_info_cs_blobs = 0x50;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L102
        off_cs_blob_csb_platform_binary = 0xb8;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_port.h#L152
        //https://github.com/0x7ff/dimentio/blob/7ffffffb4ebfcdbc46ab5e8f1becc0599a05711d/libdimentio.c#L958
        off_ipc_port_ip_kobject = 0x58;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_space.h#L128
        off_ipc_space_is_table = 0x20;
        
        off_amfi_slot = 0x8;
        off_sandbox_slot = 0x10;
        
        off_kalloc_data_external = 0xFFFFFFF007188AE8;//find_kalloc
        off_kfree_data_external = 0xFFFFFFF007189254;//find_kfree
        off_empty_kdata_page = 0xFFFFFFF0077D8000 + 0x100;
        off_trustcache = 0xFFFFFFF0078718C0;
        off_gphysbase = 0xFFFFFFF0070CBA30; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d
        off_gphyssize = 0xFFFFFFF0070CBA48; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d
        off_pmap_enter_options_addr = 0xFFFFFFF00727DDE8;//vm_map_get_pmap
        off_allproc = 0xFFFFFFF00784C100;//find_allproc
        off_pmap_find_phys = 0xFFFFFFF007284B58;
        off_ml_phys_read_data = 0xFFFFFFF00729510C;
        off_ml_phys_write_data = 0xFFFFFFF007295390;
        off_unknown = 0xFFFFFFF0071024B8;
        
    } else if (SYSTEM_VERSION_EQUAL_TO(@"15.2.1")) {
        printf("[i] offsets selected for iOS 15.2.1\n");
        //iPhone 6s 15.1 offsets
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/proc_internal.h#L227
        off_p_list_le_prev = 0x8;
        off_p_name = 0x2d9;
        off_p_pid = 0x68;
        off_p_ucred = 0;
        off_p_task = 0x10;
        off_p_csflags = 0x300;
        off_p_uid = 0x2c;
        off_p_gid = 0x30;
        off_p_ruid = 0x34;
        off_p_rgid = 0x38;
        off_p_svuid = 0x3c;
        off_p_svgid = 0x40;
        off_p_textvp = 0x358;
        off_p_pfd = 0x100;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ucred.h#L91
        off_u_cr_label = 0x78;
        off_u_cr_uid = 0x18;
        off_u_cr_ruid = 0x1c;
        off_u_cr_svuid = 0x20;
        off_u_cr_ngroups = 0x24;
        off_u_cr_groups = 0x28;
        off_u_cr_rgid = 0x68;
        off_u_cr_svgid = 0x6c;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/kern/task.h#L157
        off_task_t_flags = 0x3e8;
        off_task_itk_space = 0x308;
        off_task_map = 0x28;    //_get_task_pmap
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/vm/vm_map.h#L471
        off_vm_map_pmap = 0x48;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/arm/pmap.h#L377
        off_pmap_ttep = 0x8;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/vnode_internal.h#L142
        off_vnode_vu_ubcinfo = 0x78;
        off_vnode_v_name = 0xb8;
        off_vnode_v_parent = 0xc0;
        off_vnode_v_data = 0xe0;
        
        off_fp_glob = 0x10;
        
        off_fg_data = 0x38;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L149
        off_ubc_info_cs_blobs = 0x50;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L102
        off_cs_blob_csb_platform_binary = 0xb8;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_port.h#L152
        //https://github.com/0x7ff/dimentio/blob/7ffffffb4ebfcdbc46ab5e8f1becc0599a05711d/libdimentio.c#L958
        off_ipc_port_ip_kobject = 0x58;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_space.h#L128
        off_ipc_space_is_table = 0x20;
        
        off_amfi_slot = 0x8;
        off_sandbox_slot = 0x10;
        
        off_kalloc_data_external = 0xfffffff00718d744;//find_kalloc
        off_kfree_data_external = 0xfffffff00718df08;//find_kfree
        //off_add_x0_x0_0x40_ret = 0xFFFFFFF005C2AEC0;
        off_empty_kdata_page = 0xfffffff0077e0000 + 0x100;
        off_trustcache = 0xfffffff0078798c0;
        off_gphysbase = 0xfffffff0070cc0c0; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d
        off_gphyssize = 0xfffffff0070cc0d8; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d
        off_pmap_enter_options_addr = 0xfffffff007284884;//vm_map_get_pmap
        off_allproc = 0xfffffff007854110;//find_allproc
        off_pmap_find_phys = 0xfffffff00728b718;
        off_ml_phys_read_data = 0xfffffff00729b958;
        off_ml_phys_write_data = 0xfffffff00729bbdc;
        off_unknown = 0xfffffff007106520;
        
    } else if(SYSTEM_VERSION_EQUAL_TO(@"15.4.1")) {
        
        printf("[i] offsets selected for iOS 15.4.1\n");
        //iPhone 6s 15.4.1 offsets
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/proc_internal.h#L227
        off_p_list_le_prev = 0x8;
        off_p_name = 0x381;
        off_p_pid = 0x68;
        off_p_ucred = 0;//0xd8
        off_p_task = 0x10;
        off_p_csflags = 0x1c;//0x300
        off_p_uid = 0x2c;
        off_p_gid = 0x30;
        off_p_ruid = 0x34;
        off_p_rgid = 0x38;
        off_p_svuid = 0x44;//0x3c
        off_p_svgid = 0x48;//0x40
        off_p_textvp = 0x350;
        off_p_pfd = 0xf8;//0x100
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ucred.h#L91
        off_u_cr_label = 0x78;
        off_u_cr_uid = 0x18;
        off_u_cr_ruid = 0x1c;
        off_u_cr_svuid = 0x20;
        off_u_cr_ngroups = 0x24;
        off_u_cr_groups = 0x28;
        off_u_cr_rgid = 0x68;
        off_u_cr_svgid = 0x6c;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/kern/task.h#L157
        off_task_t_flags = 0x3e8;
        off_task_itk_space = 0x308;//0x330
        off_task_map = 0x28;    //_get_task_pmap
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/vm/vm_map.h#L471
        off_vm_map_pmap = 0x40;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/arm/pmap.h#L377
        off_pmap_ttep = 0x8;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/vnode_internal.h#L142
        off_vnode_vu_ubcinfo = 0x78;
        off_vnode_v_name = 0xb8;
        off_vnode_v_parent = 0xc0;
        off_vnode_v_data = 0xe0; // 0xd8?
        
        off_fp_glob = 0x10;
        
        off_fg_data = 0x38;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L149
        off_ubc_info_cs_blobs = 0x50;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L102
        off_cs_blob_csb_platform_binary = 0xac;//0xb8
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_port.h#L152
        //https://github.com/0x7ff/dimentio/blob/7ffffffb4ebfcdbc46ab5e8f1becc0599a05711d/libdimentio.c#L958
        off_ipc_port_ip_kobject = 0x48; //0x58
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_space.h#L128
        off_ipc_space_is_table = 0x20;
        
        off_amfi_slot = 0x8;
        off_sandbox_slot = 0x10;
        
        off_kalloc_data_external = 0xfffffff0071975f4;
        off_kfree_data_external = 0xfffffff0071981b8;
        off_empty_kdata_page = 0xfffffff0077e4000 + 0x100;
        off_trustcache = 0xfffffff00787c680;
        
        off_gphysbase = 0xfffffff007116198; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d
        off_gphyssize = 0xfffffff0071161a0; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d
        off_pmap_enter_options_addr = 0xfffffff00728a99c;
        off_allproc = 0xfffffff00785c138;
        off_pmap_find_phys = 0xfffffff007291498;
        off_ml_phys_read_data = 0xfffffff0072a1750;
        off_ml_phys_write_data = 0xfffffff0072a19b8;
        off_unknown = 0xfffffff0070ff160;
        
    } else if(SYSTEM_VERSION_EQUAL_TO(@"15.7.3")) {
        
        printf("[i] offsets selected for iOS 15.7.3\n");
        //iPhone 6s 15.7.3 offsets
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/proc_internal.h#L227
        off_p_list_le_prev = 0x8;
        off_p_name = 0x381;
        off_p_pid = 0x68;
        off_p_ucred = 0;//0xd8
        off_p_task = 0x10;
        off_p_csflags = 0x1c;//0x300
        off_p_uid = 0x2c;
        off_p_gid = 0x30;
        off_p_ruid = 0x34;
        off_p_rgid = 0x38;
        off_p_svuid = 0x44;//0x3c
        off_p_svgid = 0x48;//0x40
        off_p_textvp = 0x350;
        off_p_pfd = 0xf8;//0x100
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ucred.h#L91
        off_u_cr_label = 0x78;
        off_u_cr_uid = 0x18;
        off_u_cr_ruid = 0x1c;
        off_u_cr_svuid = 0x20;
        off_u_cr_ngroups = 0x24;
        off_u_cr_groups = 0x28;
        off_u_cr_rgid = 0x68;
        off_u_cr_svgid = 0x6c;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/kern/task.h#L157
        off_task_t_flags = 0x3e8;
        off_task_itk_space = 0x308;//0x330
        off_task_map = 0x28;    //_get_task_pmap
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/vm/vm_map.h#L471
        off_vm_map_pmap = 0x40;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/arm/pmap.h#L377
        off_pmap_ttep = 0x8;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/vnode_internal.h#L142
        off_vnode_vu_ubcinfo = 0x78;
        off_vnode_v_name = 0xb8;
        off_vnode_v_parent = 0xc0;
        off_vnode_v_data = 0xe0; // 0xd8?
        
        off_fp_glob = 0x10;
        
        off_fg_data = 0x38;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L149
        off_ubc_info_cs_blobs = 0x50;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L102
        off_cs_blob_csb_platform_binary = 0xac;//0xb8
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_port.h#L152
        //https://github.com/0x7ff/dimentio/blob/7ffffffb4ebfcdbc46ab5e8f1becc0599a05711d/libdimentio.c#L958
        off_ipc_port_ip_kobject = 0x48; //0x58
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_space.h#L128
        off_ipc_space_is_table = 0x20;
        
        off_amfi_slot = 0x8;
        off_sandbox_slot = 0x10;
        
        off_kalloc_data_external = 0xFFFFFFF00719762C;	//Maybe restruct but it's still here
        off_kfree_data_external = 0xFFFFFFF007197C98;	//One more function restruct
        off_empty_kdata_page = 0xFFFFFFF0077E0000 + 0x100;	//Kinna same struct
        off_trustcache = 0xFFFFFFF007876530;		//struct unchange
        off_gphysbase = 0xFFFFFFF007116740; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d, same struct
        off_gphyssize = 0xFFFFFFF007116748; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d, same struct
        off_pmap_enter_options_addr = 0xFFFFFFF00728C7F4;	//struct change but still remain
        off_allproc = 0xFFFFFFF007856188;			//struct unchanged
        off_pmap_find_phys = 0xFFFFFFF00729341C;		//struct unchanged
        off_ml_phys_read_data = 0xFFFFFFF0072A3828;		//struct unchanged
        off_ml_phys_write_data = 0xFFFFFFF0072A3A90;		//struct unchanged
        off_unknown = 0xFFFFFFF0070FF3D0;             //<---- I corrected it, it's not the same
        
    } else if(SYSTEM_VERSION_EQUAL_TO(@"15.6")) {
        
        printf("[i] offsets selected for iOS 15.6\n");
        //iPhone 7 15.6 offsets
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/proc_internal.h#L227
        off_p_list_le_prev = 0x8;
        off_p_name = 0x381;
        off_p_pid = 0x68;
        off_p_ucred = 0;//0xd8
        off_p_task = 0x10;
        off_p_csflags = 0x1c;//0x300
        off_p_uid = 0x2c;
        off_p_gid = 0x30;
        off_p_ruid = 0x34;
        off_p_rgid = 0x38;
        off_p_svuid = 0x44;//0x3c
        off_p_svgid = 0x48;//0x40
        off_p_textvp = 0x350;
        off_p_pfd = 0xf8;//0x100
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ucred.h#L91
        off_u_cr_label = 0x78;
        off_u_cr_uid = 0x18;
        off_u_cr_ruid = 0x1c;
        off_u_cr_svuid = 0x20;
        off_u_cr_ngroups = 0x24;
        off_u_cr_groups = 0x28;
        off_u_cr_rgid = 0x68;
        off_u_cr_svgid = 0x6c;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/kern/task.h#L157
        off_task_t_flags = 0x3e8;
        off_task_itk_space = 0x308;//0x330
        off_task_map = 0x28;    //_get_task_pmap
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/vm/vm_map.h#L471
        off_vm_map_pmap = 0x40;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/arm/pmap.h#L377
        off_pmap_ttep = 0x8;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/vnode_internal.h#L142
        off_vnode_vu_ubcinfo = 0x78;
        off_vnode_v_name = 0xb8;
        off_vnode_v_parent = 0xc0;
        off_vnode_v_data = 0xe0; // 0xd8?
        
        off_fp_glob = 0x10;
        
        off_fg_data = 0x38;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L149
        off_ubc_info_cs_blobs = 0x50;
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L102
        off_cs_blob_csb_platform_binary = 0xac;//0xb8
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_port.h#L152
        //https://github.com/0x7ff/dimentio/blob/7ffffffb4ebfcdbc46ab5e8f1becc0599a05711d/libdimentio.c#L958
        off_ipc_port_ip_kobject = 0x48; //0x58
        
        //https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_space.h#L128
        off_ipc_space_is_table = 0x20;
        
        off_amfi_slot = 0x8;
        off_sandbox_slot = 0x10;
        
        off_kalloc_data_external = 0xfffffff0071d4164;
        off_kfree_data_external = 0xfffffff0071d47d0;
        off_empty_kdata_page = 0xfffffff007820000 + 0x100;
        off_trustcache = 0xfffffff0078b6570;
        
        off_gphysbase = 0xfffffff00714e6d0; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d
        off_gphyssize = 0xfffffff00714e6d8; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d
        off_pmap_enter_options_addr = 0xfffffff0072c89b0;
        off_allproc = 0xfffffff007896198;
        off_pmap_find_phys = 0xfffffff0072cf8b4;
        off_ml_phys_read_data = 0xfffffff0072e0c94;
        off_ml_phys_write_data = 0xfffffff0072e0efc;
        off_unknown = 0xfffffff0071373e0;
        off_mac_label_set = 0xfffffff00688941c;
        off_proc_rele = 0xfffffff0075d84e8;
        off_proc_find = 0xfffffff0075d7e28;
        //OSEntitlements fffffff005a2907c
    } else {
        printf("[-] No matching offsets.\n");
        exit(EXIT_FAILURE);
    }
}



/*
//https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/proc_internal.h#L227
off_p_list_le_prev = 0x8;
off_p_name = 0x2d9;
off_p_pid = 0x68;
off_p_ucred = 0;
off_p_task = 0x10;
off_p_csflags = 0x300;
off_p_uid = 0x2c;
off_p_gid = 0x30;
off_p_ruid = 0x34;
off_p_rgid = 0x38;
off_p_svuid = 0x3c;
off_p_svgid = 0x40;
off_p_textvp = 0x2a8;
off_p_pfd = 0x100;

//https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ucred.h#L91
off_u_cr_label = 0x78;
off_u_cr_uid = 0x18;
off_u_cr_ruid = 0x1c;
off_u_cr_svuid = 0x20;
off_u_cr_ngroups = 0x24;
off_u_cr_groups = 0x28;
off_u_cr_rgid = 0x68;
off_u_cr_svgid = 0x6c;

//https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/kern/task.h#L157
off_task_t_flags = 0x3e8;
off_task_itk_space = 0x330;
off_task_map = 0x28;    //_get_task_pmap

//https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/vm/vm_map.h#L471
off_vm_map_pmap = 0x48;

//https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/arm/pmap.h#L377
off_pmap_ttep = 0x8;

//https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/vnode_internal.h#L142
off_vnode_vu_ubcinfo = 0x78;
off_vnode_v_name = 0xb8;
off_vnode_v_parent = 0xc0;
off_vnode_v_data = 0xe0;

off_fp_glob = 0x10;

off_fg_data = 0x38;

//https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L149
off_ubc_info_cs_blobs = 0x50;

//https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/ubc_internal.h#L102
off_cs_blob_csb_platform_binary = 0xb8;

//https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_port.h#L152
//https://github.com/0x7ff/dimentio/blob/7ffffffb4ebfcdbc46ab5e8f1becc0599a05711d/libdimentio.c#L958
off_ipc_port_ip_kobject = 0x58;

//https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/osfmk/ipc/ipc_space.h#L128
off_ipc_space_is_table = 0x20;

off_amfi_slot = 0x8;
off_sandbox_slot = 0x10;

off_kalloc_data_external = 0xfffffff007b91664;
off_kfree_data_external = 0xfffffff007b91f78;
off_empty_kdata_page = 0xfffffff009574000 + 0x100;
off_trustcache = 0xfffffff009772f80;
off_gphysbase = 0xfffffff0077b3ae8; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d
off_gphyssize = 0xfffffff0077b3be0; //xref pmap_attribute_cache_sync size: 0x%llx @%s:%d
off_pmap_enter_options_addr = 0xfffffff007c9f098;//vm_map_get_pmap
off_allproc = 0xfffffff009720ba0;//find_allproc
off_pmap_find_phys = 0xfffffff007ca607c;
off_ml_phys_read_data = 0xfffffff007cb9860;
off_ml_phys_write_data = 0xfffffff007cb9b58;
off_unknown = 0xfffffff0077ea6f8; */
