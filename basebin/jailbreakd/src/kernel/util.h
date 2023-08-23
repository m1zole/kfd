#import <Foundation/Foundation.h>

uint64_t proc_get_ucred(uint64_t proc_ptr);
void proc_set_ucred(uint64_t proc_ptr, uint64_t ucred_ptr);

void run_unsandboxed(void (^block)(void));