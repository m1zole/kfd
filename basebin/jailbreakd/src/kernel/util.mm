#import "util.h"
#import "krw.h"
#import "offsets.h"
#import "proc.h"
#import <libproc.h>
#import <libproc_private.h>
#import <sys/mount.h>

#define P_SUGID 0x00000100

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

NSString *proc_get_path(pid_t pid) {
  char pathbuf[4 * MAXPATHLEN];
  int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
  if (ret <= 0)
    return nil;
  return [[[NSString stringWithUTF8String:pathbuf]
      stringByResolvingSymlinksInPath] stringByStandardizingPath];
}

void proc_set_svuid(uint64_t proc_ptr, uid_t svuid) {
  kwrite32(proc_ptr + off_p_svuid, svuid);
}

void ucred_set_svuid(uint64_t ucred_ptr, uint32_t svuid) {
  kwrite32(ucred_ptr + off_u_cr_svuid, svuid);
}

void ucred_set_uid(uint64_t ucred_ptr, uint32_t uid) {
  kwrite32(ucred_ptr + off_u_cr_uid, uid);
}

void proc_set_svgid(uint64_t proc_ptr, uid_t svgid) {
  kwrite32(proc_ptr + off_p_svgid, svgid);
}

void ucred_set_svgid(uint64_t ucred_ptr, uint32_t svgid) {
  kwrite32(ucred_ptr + off_u_cr_svgid, svgid);
}

void ucred_set_cr_groups(uint64_t ucred_ptr, uint32_t cr_groups) {
  kwrite32(ucred_ptr + off_u_cr_groups, cr_groups);
}

uint32_t proc_get_p_flag(uint64_t proc_ptr) {
  return kread32(proc_ptr + off_p_flag);
}

void proc_set_p_flag(uint64_t proc_ptr, uint32_t p_flag) {
  kwrite32(proc_ptr + off_p_flag, p_flag);
}

int64_t proc_fix_setuid(pid_t pid) {
  NSString *procPath = proc_get_path(pid);
  struct stat sb;
  if (stat(procPath.fileSystemRepresentation, &sb) == 0) {
    if (S_ISREG(sb.st_mode) && (sb.st_mode & (S_ISUID | S_ISGID))) {
      uint64_t proc = proc_of_pid(pid);
      uint64_t ucred = proc_get_ucred(proc);
      if ((sb.st_mode & (S_ISUID))) {
        proc_set_svuid(proc, sb.st_uid);
        ucred_set_svuid(ucred, sb.st_uid);
        ucred_set_uid(ucred, sb.st_uid);
      }
      if ((sb.st_mode & (S_ISGID))) {
        proc_set_svgid(proc, sb.st_gid);
        ucred_set_svgid(ucred, sb.st_gid);
        ucred_set_cr_groups(ucred, sb.st_gid);
      }
      uint32_t p_flag = proc_get_p_flag(proc);
      if ((p_flag & P_SUGID) != 0) {
        p_flag &= ~P_SUGID;
        proc_set_p_flag(proc, p_flag);
      }
      return 0;
    } else {
      return 10;
    }
  } else {
    return 5;
  }
}