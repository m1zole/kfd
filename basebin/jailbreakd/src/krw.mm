#include "./common/KernelRW.hpp"
#include "./common/macros.h"
#include <Foundation/Foundation.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static KernelRW *krw = NULL;

uint64_t _kbase = 0;
uint64_t _kern_proc = 0;
uint64_t _all_proc = 0;

int get_kernel_rw(void) {
  NSLog(@"[jailbreakd] Waiting for receiving kernel r/w handoff\n");
  mach_port_t fakethread = 0;
  mach_port_t transmissionPort = 0;
  // cleanup([&] {
  //   if (transmissionPort) {
  //     mach_port_destroy(mach_task_self(), transmissionPort);
  //     transmissionPort = MACH_PORT_NULL;
  //   }
  //   if (fakethread) {
  //     thread_terminate(fakethread);
  //     mach_port_destroy(mach_task_self(), fakethread);
  //     fakethread = MACH_PORT_NULL;
  //   }
  // });
  kern_return_t kr = 0;

  retassure(!(kr = thread_create(mach_task_self(), &fakethread)),
            "[jailbreakd] Failed to create fake thread");

  // set known state
  retassure(!(kr = thread_set_exception_ports(fakethread, EXC_BREAKPOINT,
                                              MACH_PORT_NULL, EXCEPTION_DEFAULT,
                                              ARM_THREAD_STATE64)),
            "[jailbreakd] Failed to set exception port to MACH_PORT_NULL");

  // set magic state
  {
    arm_thread_state64_t state = {};
    mach_msg_type_number_t statecnt = ARM_THREAD_STATE64_COUNT;
    memset(&state, 0x41, sizeof(state));
    retassure(!(kr = thread_set_state(fakethread, ARM_THREAD_STATE64,
                                      (thread_state_t)&state,
                                      ARM_THREAD_STATE64_COUNT)),
              "[jailbreakd] Failed to set fake thread state");
  }

  // get transmission port
  {
    exception_mask_t masks[EXC_TYPES_COUNT] = {};
    mach_msg_type_number_t masksCnt = 0;
    mach_port_t eports[EXC_TYPES_COUNT] = {};
    exception_behavior_t behaviors[EXC_TYPES_COUNT] = {};
    thread_state_flavor_t flavors[EXC_TYPES_COUNT] = {};
    do {
      retassure(!(kr = thread_get_exception_ports(fakethread, EXC_BREAKPOINT,
                                                  masks, &masksCnt, eports,
                                                  behaviors, flavors)),
                "[jailbreakd] Failed to get thread exception port");
      transmissionPort = eports[0];
    } while (transmissionPort == MACH_PORT_NULL);
  }

  krw = new KernelRW();
  krw->handoffPrimitivePatching(transmissionPort);

  NSLog(@"[jailbreakd] Received Kernel R/W handoff!\n");
  krw->getOffsets(&_kbase, &_kern_proc, &_all_proc);

  NSLog(@"[jailbreakd] kbase: 0x%llx, kslide: 0x%llx, kproc: 0x%llx, allProc: "
        @"0x%llx\n",
        _kbase, _kbase - 0xfffffff007004000, _kern_proc, _all_proc);

  // krw.getOffsets(&kernelBase, &kernProc, &allProc);
  // printf("[jailbreakd] kernelBase: 0x%llx, kernProc: 0x%llx, allProc:
  // 0x%llx\n",
  //        kernelBase, kernProc, allProc);

  // uint64_t kslide = kernelBase - 0xfffffff007004000;
  // printf("[jailbreakd] kslide: 0x%llx\n", kslide);

  // uint64_t off_empty_kdata_page = 0xFFFFFFF0077D8000 + 0x100;

  // uint64_t kbaseval = krw.kread64(0xfffffff007004000 + kslide);
  // printf("[jailbreakd] kbaseval=0x%016llx\n", kbaseval);

  // uint64_t empty_kdata_page = krw.kread64(off_empty_kdata_page + kslide);
  // printf("[jailbreakd] empty_kdata_page=0x%016llx\n", empty_kdata_page);

  // printf("[jailbreakd] Writing 0x4142434445464748 to empty_kdata_page\n");
  // krw.kwrite64(off_empty_kdata_page + kslide, 0x4142434445464748);
  // printf("[jailbreakd] Did it write? empty_kdata_page=0x%016llx\n",
  //        krw.kread64(off_empty_kdata_page + kslide));
  // krw.kwrite64(off_empty_kdata_page + kslide, empty_kdata_page);

  printf("[jailbreakd] done\n");
  return 0;
}

uint64_t get_kbase(void) { return _kbase; }

uint64_t get_kslide(void) { return _kbase - 0xfffffff007004000; }

uint64_t get_kernproc(void) { return _kern_proc; }

uint64_t get_allproc(void) { return _all_proc; }

uint32_t kread32(uint64_t where) {
  if (krw)
    return krw->kread32(where);
  return 0;
}
uint64_t kread64(uint64_t where) {
  if (krw)
    return krw->kread64(where);
  return 0;
}

void kwrite32(uint64_t where, uint32_t what) {
  if (krw) {
    krw->kwrite32(where, what);
  }
}
void kwrite64(uint64_t where, uint64_t what) {
  if (krw) {
    krw->kwrite64(where, what);
  }
}

size_t kreadbuf(uint64_t kaddr, void *output, size_t size) {
  if (krw) {
    return krw->kreadbuf(kaddr, output, size);
  }
  return 0;
}

size_t kwritebuf(uint64_t kaddr, const void *input, size_t size) {
  if (krw) {
    return krw->kwritebuf(kaddr, input, size);
  }
  return 0;
}

void kwrite8(uint64_t where, uint8_t what) {
  if (krw) {
    kwritebuf(where, &what, sizeof(uint8_t));
  }
}

void kwrite16(uint64_t where, uint16_t what) {
  if (krw) {
    kwritebuf(where, &what, sizeof(uint16_t));
  }
}

uint8_t kread8(uint64_t where) {
  uint8_t out = 0;
  if (krw) {
    kreadbuf(where, &out, sizeof(uint8_t));
  }
  return out;
}

uint16_t kread16(uint64_t where) {
  uint16_t out = 0;
  if (krw) {
    kreadbuf(where, &out, sizeof(uint16_t));
  }
  return out;
}