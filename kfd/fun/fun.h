//
//  fun.h
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/07/25.
//

#ifndef fun_h
#define fun_h

#include <stdio.h>
#include <IOKit/IOKitLib.h>

typedef mach_port_t io_object_t;
typedef io_object_t io_service_t, io_connect_t, io_registry_entry_t;
extern const mach_port_t kIOMasterPortDefault;

void do_fun(char** enabledTweaks, int numTweaks);
void backboard_respring(void);
int funUcred(uint64_t proc);
int funCSFlags(char* process);
int funTask(char* process);
uint64_t fun_ipc_entry_lookup(mach_port_name_t port_name);

#endif /* fun_h */
