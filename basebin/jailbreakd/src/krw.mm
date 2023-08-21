#import <mach/mach.h>

#import "krw.h"
#import "./common/macros.h"
#import "./common/KernelRW.hpp"

static KernelRW *krw = NULL;

static uint64_t kernelBase = 0;
static uint64_t kernProc = 0;
static uint64_t allProc = 0;

// 15.1 offsets
uint32_t off_p_pid = 0x68;
uint32_t off_p_list_le_prev = 0x8;
uint32_t off_p_ucred = 0xd8;

extern "C" void get_kernel_rw(void) {
  mach_port_t fakethread = 0;
  mach_port_t transmissionPort = 0;
  cleanup([&] {
    if (transmissionPort) {
      mach_port_destroy(mach_task_self(), transmissionPort);
      transmissionPort = MACH_PORT_NULL;
    }
    if (fakethread) {
      thread_terminate(fakethread);
      mach_port_destroy(mach_task_self(), fakethread);
      fakethread = MACH_PORT_NULL;
    }
  });
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

  krw.handoffPrimitivePatching(transmissionPort);
  NSLog(@"[jailbreakd] handoff done!");

  krw.getOffsets(&kernelBase, &kernProc, &allProc);
  NSLog(@"[jailbreakd] kernelBase: 0x%llx, kernProc: 0x%llx, allProc: 0x%llx",
        kernelBase, kernProc, allProc);
}

extern "C" size_t kread(uint64_t addr, void *p, size_t size) {
  if (krw) {
    return krw->kreadbuf(addr, p, size);
  }
  return 0;
}

extern "C" uint8_t kread8(uint64_t where) {
  uint8_t out;
  if (krw) {
    return krw->kreadbuf(where, &out, sizeof(uint8_t));
  }
  return 0;
}

extern "C" uint32_t kread16(uint64_t where) {
  uint16_t out;
  if (krw) {
    return krw->kreadbuf(where, &out, sizeof(uint16_t));
  }
  return 0;
}
extern "C" uint32_t kread32(uint64_t where) {
  uint32_t out;
  if (krw) {
    return krw->kreadbuf(where, &out, sizeof(uint32_t));
  }
  return 0;
}
extern "C" uint64_t kread64(uint64_t where) {
  uint64_t out;
  if (krw) {
    return krw->kreadbuf(where, &out, sizeof(uint64_t));
  }
  return 0;
}

extern "C" void kwrite32(uint64_t where, uint32_t what) {
  if (krw) {
    krw->kwrite32(where, what);
  }
}
extern "C" void kwrite64(uint64_t where, uint64_t what) {
  if (krw) {
    krw->kwrite64(addr, val);
  }
}

extern "C" size_t kwrite(uint64_t where, const void *p, size_t size) {
  if (krw) {
    uint64_t endAddr = kaddr + size;
    uint32_t inputOffset = 0;
    unsigned char *inputBytes = (unsigned char *)input;

    for (uint64_t curAddr = kaddr; curAddr < endAddr; curAddr += 4) {
      uint32_t toWrite = 0;
      int bc = 4;

      uint64_t remainingBytes = endAddr - curAddr;
      if (remainingBytes < 4) {
        toWrite = kread32(curAddr);
        bc = (int)remainingBytes;
      }

      unsigned char *wb = (unsigned char *)&toWrite;
      for (int i = 0; i < bc; i++) {
        wb[i] = inputBytes[inputOffset];
        inputOffset++;
      }

      kwrite32(curAddr, toWrite);
    }
  }
  return 0;
}

extern "C" void kwrite8(uint64_t where, uint8_t what) {
  if (krw) {
    kwrite(where, &what, sizeof(uint8_t));
  }
}

extern "C" void kwrite16(uint64_t where, uint16_t what) {
  if (krw) {
    kwrite(where, &what, sizeof(uint16_t));
  }
}

uint64_t proc_of_pid(pid_t pid) {
  uint64_t proc = kernelProc;

  while (true) {
    if (kread32(proc + off_p_pid) == pid) {
      return proc;
    }
    proc = kread64(proc + off_p_list_le_prev);
    if (!proc) {
      return -1;
    }
  }

  return 0;
}

uint64_t self_proc(void) { return proc_of_pid(getpid()); }

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

void run_unsandboxed(void (^block)(void)) {
  pid_t self_pid = getpid();

  uint64_t self_ucreds = borrow_ucreds(self_pid, 0);
  block();
  unborrow_ucreds(self_pid, self_ucreds);
}

uint64_t vm_map_get_header(uint64_t vm_map_ptr)
{
	return vm_map_ptr + 0x10;
}

uint64_t vm_map_header_get_first_entry(uint64_t vm_header_ptr)
{
	return kread64(vm_header_ptr + 0x8);
}

uint32_t vm_header_get_nentries(uint64_t vm_header_ptr)
{
	return kread32(vm_header_ptr + 0x20);
}

void vm_entry_get_range(uint64_t vm_entry_ptr, uint64_t *start_address_out, uint64_t *end_address_out)
{
	uint64_t range[2];
	kread(vm_entry_ptr + 0x10, &range[0], sizeof(range));
	if (start_address_out) *start_address_out = range[0];
	if (end_address_out) *end_address_out = range[1];
}

uint64_t vm_map_entry_get_next_entry(uint64_t vm_entry_ptr)
{
	return kread64(vm_entry_ptr + 0x8);
}

#define FLAGS_PROT_SHIFT    7
#define FLAGS_MAXPROT_SHIFT 11
//#define FLAGS_PROT_MASK     0xF << FLAGS_PROT_SHIFT
//#define FLAGS_MAXPROT_MASK  0xF << FLAGS_MAXPROT_SHIFT
#define FLAGS_PROT_MASK    0x780
#define FLAGS_MAXPROT_MASK 0x7800

void vm_map_entry_get_prot(uint64_t entry_ptr, vm_prot_t *prot, vm_prot_t *max_prot)
{
	uint64_t flags = kread64(entry_ptr + 0x48);
	if (prot) *prot = (flags >> FLAGS_PROT_SHIFT) & 0xF;
	if (max_prot) *max_prot = (flags >> FLAGS_MAXPROT_SHIFT) & 0xF;
}

void vm_map_entry_set_prot(uint64_t entry_ptr, vm_prot_t prot, vm_prot_t max_prot)
{
	uint64_t flags = kread64(entry_ptr + 0x48);
	uint64_t new_flags = flags;
	new_flags = (new_flags & ~FLAGS_PROT_MASK) | ((uint64_t)prot << FLAGS_PROT_SHIFT);
	new_flags = (new_flags & ~FLAGS_MAXPROT_MASK) | ((uint64_t)max_prot << FLAGS_MAXPROT_SHIFT);
	if (new_flags != flags) {
		kwrite64(entry_ptr + 0x48, new_flags);
	}
}

uint64_t proc_get_pptr(uint64_t proc_ptr) { return kread64(proc_ptr + 0x18); }

uint64_t proc_get_task(uint64_t proc_ptr) { return kread64(proc_ptr + 0x10); }

uint64_t task_get_vm_map(uint64_t task_ptr) { return kread64(task_ptr + 0x28); }

uint64_t vm_map_get_pmap(uint64_t vm_map_ptr) {
  return kread64(vm_map_ptr + 0x48 /*bootInfo_getUInt64(@"VM_MAP_PMAP")*/);
}

void pmap_set_wx_allowed(uint64_t pmap_ptr, bool wx_allowed) {
  uint64_t kernel_el = 4 /*bootInfo_getUInt64(@"kernel_el")*/;
  uint32_t el2_adjust = (kernel_el == 8) ? 8 : 0;
  kwrite8(pmap_ptr + 0xC2 + el2_adjust, wx_allowed);
}

uint32_t proc_get_csflags(uint64_t proc) { 
  return kread32(proc + 0x300); 
}

void task_set_memory_ownership_transfer(uint64_t task_ptr, uint8_t enabled)
{
	kwrite8(task_ptr + 0x5b0, enabled);
}

vm_map_flags vm_map_get_flags(uint64_t vm_map_ptr)
{
	vm_map_flags flags;
	kread(vm_map_ptr + 0x11C, &flags, sizeof(flags));
	return flags;
}

void vm_map_set_flags(uint64_t vm_map_ptr, vm_map_flags new_flags)
{
	kwrite(vm_map_ptr + 0x11C, &new_flags, sizeof(new_flags));
}

int proc_set_debugged(uint64_t proc_ptr, bool fully_debugged) {
  uint64_t task = proc_get_task(proc_ptr);
  uint64_t vm_map = task_get_vm_map(task);
  uint64_t pmap = vm_map_get_pmap(vm_map);

  // For most unrestrictions, just setting wx_allowed is enough
  // This enabled hooks without being detectable at all, as cs_ops will not
  // return CS_DEBUGGED
  pmap_set_wx_allowed(pmap, true);

  if (fully_debugged) {
    // When coming from ptrace, we want to fully emulate cs_allow_invalid though

    uint32_t flags = proc_get_csflags(proc_ptr) & ~(CS_KILL | CS_HARD);
    if (flags & CS_VALID) {
      flags |= CS_DEBUGGED;
    }
    proc_set_csflags(proc_ptr, flags);

    task_set_memory_ownership_transfer(task, true);

    vm_map_flags map_flags = vm_map_get_flags(vm_map);
    map_flags.switch_protect = false;
    map_flags.cs_debugged = true;
    vm_map_set_flags(vm_map, map_flags);
  }
  return 0;
}
