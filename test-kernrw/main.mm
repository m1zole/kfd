#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <mach/mach.h>
#include "macros.h"
#include "KernelRW.hpp"

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>


int main(int argc, char **argv, char **envp){
	printf("[test-kernrw] Hello World! TODO: Get kernel r/w\n");
	mach_port_t fakethread = 0;
	mach_port_t transmissionPort = 0;
	cleanup([&]{
		if (transmissionPort) {
			mach_port_destroy(mach_task_self(), transmissionPort); transmissionPort = MACH_PORT_NULL;
		}
		if (fakethread) {
			thread_terminate(fakethread);
			mach_port_destroy(mach_task_self(), fakethread); fakethread = MACH_PORT_NULL;
		}
	});
	kern_return_t kr = 0;
	KernelRW krw;

	retassure(!(kr = thread_create(mach_task_self(), &fakethread)), "[test-kernrw] Failed to create fake thread");

	//set known state
	retassure(!(kr = thread_set_exception_ports(fakethread, EXC_BREAKPOINT, MACH_PORT_NULL, EXCEPTION_DEFAULT, ARM_THREAD_STATE64)), "[test-kernrw] Failed to set exception port to MACH_PORT_NULL");

	//set magic state
	{
		arm_thread_state64_t state = {};
		mach_msg_type_number_t statecnt = ARM_THREAD_STATE64_COUNT;
		memset(&state, 0x41, sizeof(state));
		retassure(!(kr = thread_set_state(fakethread, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT)), "[test-kernrw] Failed to set fake thread state");
	}

	//get transmission port
	{
		exception_mask_t masks[EXC_TYPES_COUNT] = {};
		mach_msg_type_number_t masksCnt = 0;
		mach_port_t eports[EXC_TYPES_COUNT] = {};
		exception_behavior_t behaviors[EXC_TYPES_COUNT] = {};
		thread_state_flavor_t flavors[EXC_TYPES_COUNT] = {};
		do {
			retassure(!(kr = thread_get_exception_ports(fakethread, EXC_BREAKPOINT, masks, &masksCnt, eports, behaviors, flavors)), "[test-kernrw] Failed to get thread exception port");
			transmissionPort = eports[0];
		}while(transmissionPort == MACH_PORT_NULL);
	}

	krw.handoffPrimitivePatching(transmissionPort);
	printf("[test-kernrw] handoff done!\n");

//	uint64_t kbase = krw.getKernelBase();
//	printf("kernelbase=0x%016llx\n",kbase);
    uint64_t kernelBase = 0;
    uint64_t kernProc = 0;
    uint64_t allProc = 0;
    
    krw.getOffsets(&kernelBase, &kernProc, &allProc);
    printf("kernelBase: 0x%llx, kernProc: 0x%llx, allProc: 0x%llx\n", kernelBase, kernProc, allProc);
    
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:@"/tmp/kfd-arm64.plist"];
    uint64_t kslide = [dict[@"kslide"] unsignedLongLongValue];
    
    uint64_t off_empty_kdata_page = 0xFFFFFFF0077D8000 + 0x100;
    
	sleep(1);
	uint64_t kbaseval = krw.kread64(0xfffffff007004000 + kslide);
	printf("[test-kernrw] kbaseval=0x%016llx\n",kbaseval);
    
    uint64_t empty_kdata_page = krw.kread64(off_empty_kdata_page + kslide);
    printf("[test-kernrw] empty_kdata_page=0x%016llx\n",empty_kdata_page);
    
    printf("[test-kernrw] Writing 0x4142434445464748 to empty_kdata_page\n");
    krw.kwrite64(off_empty_kdata_page + kslide, 0x4142434445464748);
    printf("[test-kernrw] Did it write? empty_kdata_page=0x%016llx\n",krw.kread64(off_empty_kdata_page + kslide));
    krw.kwrite64(off_empty_kdata_page + kslide, empty_kdata_page);

	printf("[test-kernrw] done\n");
	return 0;
}
