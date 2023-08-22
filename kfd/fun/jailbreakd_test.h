//
//  jailbreakd_test.h
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/22.
//

#import <stdio.h>
#import <stdbool.h>
#import <mach/mach.h>

//
//  jailbreakd_test.c
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/22.
//

typedef void * xpc_object_t;
typedef xpc_object_t xpc_pipe_t;
xpc_object_t xpc_array_create_empty(void);
xpc_object_t xpc_dictionary_create_empty(void);
void xpc_array_set_string(xpc_object_t xarray, size_t index, const char *string);
void xpc_dictionary_set_uint64(xpc_object_t xdict, const char *key, uint64_t value);
void xpc_dictionary_set_bool(xpc_object_t xdict, const char *key, bool value);
void xpc_dictionary_set_value(xpc_object_t xdict, const char *key, xpc_object_t _Nullable value);
char * xpc_copy_description(xpc_object_t object);
int64_t xpc_dictionary_get_int64(xpc_object_t xdict, const char *key);
uint64_t xpc_dictionary_get_uint64(xpc_object_t xdict, const char *key);
char *xpc_strerror (int);
int xpc_pipe_routine_with_flags(xpc_pipe_t xpipe, xpc_object_t xdict, xpc_object_t* reply, uint64_t flags);
kern_return_t bootstrap_look_up(mach_port_t port, const char *service, mach_port_t *server_port);
xpc_object_t xpc_pipe_create_from_port(mach_port_t port, uint32_t flags);
int xpc_pipe_routine (xpc_object_t xpc_pipe, xpc_object_t inDict, xpc_object_t **out);
#define XPC_ARRAY_APPEND ((size_t)(-1))
#define ROUTINE_LOAD   800
#define ROUTINE_UNLOAD 801

mach_port_t jbdMachPort(void);
xpc_object_t sendJBDMessage(xpc_object_t xdict);
void test_run_jailbreakd(void);
void* test_run_jailbreakd_async(void* arg);
void test_handoffKRW_jailbreakd(void);
void test_communicate_jailbreakd(void);
