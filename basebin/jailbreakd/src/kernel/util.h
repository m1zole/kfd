#import <Foundation/Foundation.h>

uint64_t proc_get_ucred(uint64_t proc_ptr);
void proc_set_ucred(uint64_t proc_ptr, uint64_t ucred_ptr);

void run_unsandboxed(void (^block)(void));

NSString *proc_get_path(pid_t pid);
void proc_set_svuid(uint64_t proc_ptr, uid_t svuid);
void ucred_set_svuid(uint64_t ucred_ptr, uint32_t svuid);
void ucred_set_uid(uint64_t ucred_ptr, uint32_t uid);

void proc_set_svgid(uint64_t proc_ptr, uid_t svgid);
void ucred_set_svgid(uint64_t ucred_ptr, uint32_t svgid);
void ucred_set_cr_groups(uint64_t ucred_ptr, uint32_t cr_groups);

uint32_t proc_get_p_flag(uint64_t proc_ptr);
void proc_set_p_flag(uint64_t proc_ptr, uint32_t p_flag);

int64_t proc_fix_setuid(pid_t pid);