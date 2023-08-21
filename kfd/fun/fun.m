//
//  fun.m
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/10.
//

#import <Foundation/Foundation.h>
#import <spawn.h>
#import <sys/stat.h>
#import <pthread.h>
#import "krw.h"
#import "offsets.h"
#import "sandbox.h"
#import "trustcache.h"
#import "escalate.h"
#import "utils.h"
#import "fun.h"
#import "proc.h"
#import "vnode.h"
#import "dropbear.h"
#import "./common/KernelRwWrapper.h"
#import "bootstrap.h"
#import "boot_info.h"

//#import <xpc/xpc.h>
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
char *xpc_strerror (int);
int xpc_pipe_routine_with_flags(xpc_pipe_t xpipe, xpc_object_t xdict, xpc_object_t* reply, uint64_t flags);
kern_return_t bootstrap_look_up(mach_port_t port, const char *service, mach_port_t *server_port);
xpc_object_t xpc_pipe_create_from_port(mach_port_t port, uint32_t flags);
int xpc_pipe_routine (xpc_object_t xpc_pipe, xpc_object_t inDict, xpc_object_t **out);
#define XPC_ARRAY_APPEND ((size_t)(-1))
#define ROUTINE_LOAD   800
#define ROUTINE_UNLOAD 801

void test_kalloc_kfree(void) {
    size_t allocated_size = 0x1000;
    uint64_t allocated_kmem = kalloc(allocated_size);
    kwrite64(allocated_kmem, 0x4142434445464748);
    printf("[+] allocated_kmem: 0x%llx\n", allocated_kmem);
    HexDump(allocated_kmem, allocated_size);
    
    kfree(allocated_kmem, allocated_size);
}

void test_unsandbox(void) {
    char* _token = token_by_sandbox_extension_issue_file("com.apple.app-sandbox.read-write", "/", 0);
    printf("consume ret: %lld\n", sandbox_extension_consume(_token));
    char* _token2 = token_by_sandbox_extension_issue_file("com.apple.sandbox.executable", "/", 0);
    printf("token2: %s\n", _token2);
    printf("consume ret: %lld\n", sandbox_extension_consume(_token2));
}

void test_load_trustcache(void) {
    const char* path = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/unsignedhelloworld"].UTF8String;
    chmod(path, 0755);
    printf("unsigned binaries path: %s\n", path);
    
    NSString* tcpath = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/binaries.tc"];
    
    uint64_t trustCacheKaddr = staticTrustCacheUploadFileAtPath(tcpath, NULL);
    printf("trustCacheKaddr: 0x%llx\n", trustCacheKaddr);
    util_runCommand(path, NULL, NULL);
    trustCacheListRemove(trustCacheKaddr);
}

void test_load_trustcache2(void) {
    const char* path = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/tar"].UTF8String;
    chmod(path, 0755);
    printf("unsigned binaries path: %s\n", path);
    
    NSString* tcpath = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/binaries.tc"];
    
    uint64_t trustCacheKaddr = staticTrustCacheUploadFileAtPath(tcpath, NULL);
    printf("trustCacheKaddr: 0x%llx\n", trustCacheKaddr);
    util_runCommand(path, NULL, NULL);
    trustCacheListRemove(trustCacheKaddr);
}

void* test_run_testkernrw(void* arg) {
    const char* path = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/test-kernrw"].UTF8String;
    util_runCommand(path, NULL, NULL);
    return NULL;
}

void test_handoffKRW(void) {
    NSString* tcpath = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/binaries.tc"];
    uint64_t trustCacheKaddr = staticTrustCacheUploadFileAtPath(tcpath, NULL);
    printf("trustCacheKaddr: 0x%llx\n", trustCacheKaddr);
    
    const char* path = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/test-kernrw"].UTF8String;
    chmod(path, 0755);
    
    pthread_t thread;
    if (pthread_create(&thread, NULL, test_run_testkernrw, NULL) != 0) {
        perror("pthread_create failed");
        return;
    }
    usleep(10000);
    pid_t test_pid = pid_by_name("test-kernrw");
    handoffKernRw(test_pid, path);
}

struct _os_alloc_once_s {
    long once;
    void *ptr;
};

struct xpc_global_data {
    uint64_t    a;
    uint64_t    xpc_flags;
    mach_port_t    task_bootstrap_port;  /* 0x10 */
#ifndef _64
    uint32_t    padding;
#endif
    xpc_object_t    xpc_bootstrap_pipe;   /* 0x18 */
    // and there's more, but you'll have to wait for MOXiI 2 for those...
    // ...
};

extern struct _os_alloc_once_s _os_alloc_once_table[];
extern void* _os_alloc_once(struct _os_alloc_once_s *slot, size_t sz, os_function_t init);

xpc_object_t launchd_xpc_send_message(xpc_object_t xdict)
{
    void* pipePtr = NULL;
    
    if(_os_alloc_once_table[1].once == -1)
    {
        pipePtr = _os_alloc_once_table[1].ptr;
    }
    else
    {
        pipePtr = _os_alloc_once(&_os_alloc_once_table[1], 472, NULL);
        if (!pipePtr) _os_alloc_once_table[1].once = -1;
    }

    xpc_object_t xreply = nil;
    if (pipePtr) {
        struct xpc_global_data* globalData = pipePtr;
        xpc_object_t pipe = globalData->xpc_bootstrap_pipe;
        if (pipe) {
            int err = xpc_pipe_routine_with_flags(pipe, xdict, &xreply, 0);
            if (err != 0) {
                return nil;
            }
        }
    }
    return xreply;
}

int64_t launchctl_load(const char* plistPath, bool unload)
{
    xpc_object_t pathArray = xpc_array_create_empty();
    xpc_array_set_string(pathArray, XPC_ARRAY_APPEND, plistPath);
    
    xpc_object_t msgDictionary = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(msgDictionary, "subsystem", 3);
    xpc_dictionary_set_uint64(msgDictionary, "handle", 0);
    xpc_dictionary_set_uint64(msgDictionary, "type", 1);
    xpc_dictionary_set_bool(msgDictionary, "legacy-load", true);
    xpc_dictionary_set_bool(msgDictionary, "enable", false);
    xpc_dictionary_set_uint64(msgDictionary, "routine", unload ? ROUTINE_UNLOAD : ROUTINE_LOAD);
    xpc_dictionary_set_value(msgDictionary, "paths", pathArray);
    
    xpc_object_t msgReply = launchd_xpc_send_message(msgDictionary);

    char *msgReplyDescription = xpc_copy_description(msgReply);
    printf("msgReply = %s\n", msgReplyDescription);
    free(msgReplyDescription);
    
    int64_t bootstrapError = xpc_dictionary_get_int64(msgReply, "bootstrap-error");
    if(bootstrapError != 0)
    {
        printf("bootstrap-error = %s\n", xpc_strerror((int32_t)bootstrapError));
        return bootstrapError;
    }
    
    int64_t error = xpc_dictionary_get_int64(msgReply, "error");
    if(error != 0)
    {
        printf("error = %s\n", xpc_strerror((int32_t)error));
        return error;
    }
    
    // launchctl seems to do extra things here
    // like getting the audit token via xpc_dictionary_get_audit_token
    // or sometimes also getting msgReply["req_pid"] and msgReply["rec_execcnt"]
    // but we don't really care about that here

    return 0;
}

mach_port_t jbdMachPort(void)
{
    mach_port_t outPort = -1;

    if (getpid() == 1) {
        mach_port_t self_host = mach_host_self();
        host_get_special_port(self_host, HOST_LOCAL_NODE, 16, &outPort);
        mach_port_deallocate(mach_task_self(), self_host);
    }
    else {
        bootstrap_look_up(bootstrap_port, "kr.h4ck.jailbreakd", &outPort);
    }

    return outPort;
}


xpc_object_t sendJBDMessage(xpc_object_t xdict)
{
    xpc_object_t xreply = nil;
    mach_port_t jbdPort = jbdMachPort();
    if (jbdPort != -1) {
        xpc_object_t pipe = xpc_pipe_create_from_port(jbdPort, 0);
        if (pipe) {
            int err = xpc_pipe_routine(pipe, xdict, &xreply);
            if (err != 0) {
                printf("xpc_pipe_routine error on sending message to jailbreakd: %d / %s\n", err, xpc_strerror(err));
                xreply = nil;
            };
        }
        mach_port_deallocate(mach_task_self(), jbdPort);
    }
    return xreply;
}

void test_run_jailbreakd(void) {
    util_runCommand("/var/jb/basebin/jbinit", NULL, NULL);
    //launchctl_load(prebootPath(@"basebin/LaunchDaemons/kr.h4ck.jailbreakd.plist").fileSystemRepresentation, false);
}

void test_communicate_jailbreakd(void) {
    xpc_object_t message = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(message, "id", 0x4141);
    
    xpc_object_t reply = sendJBDMessage(message);
    printf("reply: %p\n", reply);   //if value have (not 0), then communicate successful!
}

int do_fun(void) {
    printf("do_fun start!\n");
    usleep(1000000);

    uint64_t kslide = get_kslide();
    uint64_t kbase = 0xfffffff007004000 + kslide;
    
    printf("[i] Kernel base: 0x%llx\n", kbase);
    printf("[i] Kernel slide: 0x%llx\n", kslide);
    printf("[i] Kernel base kread64 ret: 0x%llx\n", kread64(kbase));
    
    printf("[i] rootify ret: %d\n", rootify(getpid()));
    printf("[i] uid: %d, gid: %d\n", getuid(), getgid());

    prepare_kcall();
    
    platformize(getpid());
    
    uint64_t sb = unsandbox(getpid());
    
    //do some stuff here...
    loadTrustCache();
    extractBootstrap();
    runSSH();
    
    test_handoffKRW();
    
    test_run_jailbreakd();
    
    test_communicate_jailbreakd();
    
    sandbox(getpid(), sb);
    
    term_kcall();

    
    
    return 0;
}
