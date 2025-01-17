#ifndef PATCHFINDER64_H_
#define PATCHFINDER64_H_

int kpf_init_kernel(uint64_t base, const char *filename);
void term_kernel(void);

enum { SearchInCore, SearchInPrelink, SearchInPPL };

uint64_t find_register_value(uint64_t where, int reg);
uint64_t find_reference(uint64_t to, int n, int prelink);
uint64_t find_strref(const char *string, int n, int prelink);
uint64_t find_kdata(void);
uint64_t find_mac_label_set(void);
uint64_t find_proc_find(void);
uint64_t find_proc_rele(void);
uint64_t find_gPhysBase(void);
uint64_t find_gPhySize(void);
uint64_t find_ptov_table(void);
uint64_t find_kernel_pmap(void);
uint64_t find_amfiret(void);
uint64_t find_ret_0(void);
uint64_t find_amfi_memcmpstub(void);
uint64_t find_sbops(void);
uint64_t find_lwvm_mapio_patch(void);
uint64_t find_lwvm_mapio_newj(void);
uint64_t find_ml_phys_read_data(void);
uint64_t find_ml_phys_write_data(void);
uint64_t find_off_trustcache(void);
uint64_t pmap_enter_options(void);

uint64_t find_entry(void);
const unsigned char *find_mh(void);

uint64_t find_cpacr_write(void);
uint64_t find_str(const char *string);
uint64_t find_amfiops(void);
uint64_t find_sysbootnonce(void);
uint64_t find_trustcache(void);
uint64_t find_amficache(void);
uint64_t find_allproc(void);
uint64_t find_kauth_cred_table_anchor(void);
uint64_t find_cache(int dynamic);

uint64_t find_add_x0_x0_0x40_ret(void);
uint64_t find_vnode_lookup(void);
uint64_t find_vnode_put(void);
uint64_t find_vfs_context_current(void);
uint64_t find_rootvnode(void);
uint64_t find_zone_map_ref(void);

uint64_t find_pmap_initialize_legacy_static_trust_cache_ppl(void);
uint64_t find_trust_cache_ppl(void);

#endif
