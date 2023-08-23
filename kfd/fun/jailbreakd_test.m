//
//  jailbreakd_test.c
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/22.
//

#import <Foundation/Foundation.h>
#import "jailbreakd_test.h"
#import "utils.h"
#import "offsets.h"
#import "krw.h"
#import "./common/KernelRwWrapper.h"
#import "proc.h"

#import <stdbool.h>
#import <mach/mach.h>
#import <stdlib.h>
#import <unistd.h>
#import <pthread.h>
#import <sys/stat.h>

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
}

void* test_run_jailbreakd_async(void* arg) {
    util_runCommand("/var/jb/basebin/jbinit", NULL, NULL);
    return NULL;
}

void test_handoffKRW_jailbreakd(void) {
    pthread_t thread;
    if (pthread_create(&thread, NULL, test_run_jailbreakd_async, NULL) != 0) {
        perror("pthread_create failed");
        return;
    }
    usleep(100000);
    pid_t jbd_pid = pid_by_name("jailbreakd");
    handoffKernRw(jbd_pid, "/var/jb/basebin/jailbreakd");
}

uint64_t test_jbd_kcall(uint64_t func, uint64_t argc, const uint64_t *argv)
{
    xpc_object_t message = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(message, "id", JBD_MSG_KCALL);
    xpc_dictionary_set_uint64(message, "kaddr", func);

    xpc_object_t args = xpc_array_create_empty();
    for (uint64_t i = 0; i < argc; i++) {
        xpc_array_set_uint64(args, XPC_ARRAY_APPEND, argv[i]);
    }
    xpc_dictionary_set_value(message, "args", args);

    xpc_object_t reply = sendJBDMessage(message);
    if (!reply) return -1;
    return xpc_dictionary_get_uint64(reply, "ret");
}

void test_communicate_jailbreakd(void) {
    //testing 0x1 = check if kernel r/w received
    xpc_object_t message = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(message, "id", JBD_MSG_KRW_READY);
    
    xpc_object_t reply = sendJBDMessage(message);
    if(!reply) {
        printf("Failed to get reply from jailbreakd\n");
        return;
    }
    
    uint64_t krw_ready = xpc_dictionary_get_uint64(reply, "krw_ready");
    printf("krw_ready: 0x%llx\n", krw_ready); //should return 1
    
    //testing 0x2 = grab kernel info
    message = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(message, "id", JBD_MSG_KERNINFO);
    
    reply = sendJBDMessage(message);
    if(!reply) {
        printf("Failed to get reply from jailbreakd\n");
        return;
    }
    
    uint64_t kbase = xpc_dictionary_get_uint64(reply, "kbase");
    uint64_t kslide = xpc_dictionary_get_uint64(reply, "kslide");
    uint64_t allproc = xpc_dictionary_get_uint64(reply, "allproc");
    uint64_t kernproc = xpc_dictionary_get_uint64(reply, "kernproc");
    
    printf("Got reply from jailbreakd\n");
    printf("kbase = 0x%llx\n", kbase);
    printf("kslide = 0x%llx\n", kslide);
    printf("allproc = 0x%llx\n", allproc);
    printf("kernproc = 0x%llx\n", kernproc);
    
    //testing 0x3 = kread32
    message = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(message, "id", JBD_MSG_KREAD32);
    xpc_dictionary_set_uint64(message, "kaddr", kbase);
    
    reply = sendJBDMessage(message);
    if(!reply) {
        printf("Failed to get reply from jailbreakd\n");
        return;
    }
    uint64_t val = xpc_dictionary_get_uint64(reply, "ret");
    printf("kread32 ret: 0x%llx\n", val);
    
    //testing 0x4 = kread64
    message = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(message, "id", JBD_MSG_KREAD64);
    xpc_dictionary_set_uint64(message, "kaddr", kbase);
    
    reply = sendJBDMessage(message);
    if(!reply) {
        printf("Failed to get reply from jailbreakd\n");
        return;
    }
    uint64_t ret = xpc_dictionary_get_uint64(reply, "ret");
    printf("kread64 ret: 0x%llx\n", ret);
    
    //testing 0x5 = kwrite32
    message = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(message, "id", JBD_MSG_KWRITE32);
    xpc_dictionary_set_uint64(message, "kaddr", off_empty_kdata_page + kslide);
    xpc_dictionary_set_uint64(message, "val", 0x41424344);
    
    reply = sendJBDMessage(message);
    if(!reply) {
        printf("Failed to get reply from jailbreakd\n");
        return;
    }
    ret = xpc_dictionary_get_uint64(reply, "ret");
    printf("kwrite32 ret: 0x%llx\n", ret);
    
    printf("really off_empty_kdata_page has been written? 0x%x\n", kread32(off_empty_kdata_page + get_kslide()));
    
    //testing 0x6 = kwrite64
    message = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(message, "id", JBD_MSG_KWRITE64);
    xpc_dictionary_set_uint64(message, "kaddr", off_empty_kdata_page + kslide);
    xpc_dictionary_set_uint64(message, "val", 0x4141414141414141);
    
    reply = sendJBDMessage(message);
    if(!reply) {
        printf("Failed to get reply from jailbreakd\n");
        return;
    }
    ret = xpc_dictionary_get_uint64(reply, "ret");
    printf("kwrite64 ret: 0x%llx\n", ret);
    
    printf("really off_empty_kdata_page has been written? 0x%llx\n", kread64(off_empty_kdata_page + get_kslide()));
    
    //Restore
    kwrite64(off_empty_kdata_page + get_kslide(), 0x0);
    
    //testing 0x7 = kalloc
    message = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(message, "id", JBD_MSG_KALLOC);
    xpc_dictionary_set_uint64(message, "ksize", 0x100);

    reply = sendJBDMessage(message);
    if(!reply) {
        printf("Failed to get reply from jailbreakd\n");
        return;
    }
    ret = xpc_dictionary_get_uint64(reply, "ret");
    printf("kalloc mem: 0x%llx\n", ret);
//
//
//    //testing 0x8 = kfree
    message = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(message, "id", JBD_MSG_KFREE);
    xpc_dictionary_set_uint64(message, "kaddr", ret);
    xpc_dictionary_set_uint64(message, "ksize", 0x100);

    reply = sendJBDMessage(message);
    if(!reply) {
        printf("Failed to get reply from jailbreakd\n");
        return;
    }
    ret = xpc_dictionary_get_uint64(reply, "ret");
    printf("kfree ret: 0x%llx\n", ret);

    //testing 0x9 = kcall
    //0xFFFFFFF00758E90C proc_selfpid
    uint64_t kcall_ret = test_jbd_kcall(0xFFFFFFF00758E90C + kslide, 1, (const uint64_t[]){1});
    printf("proc_selfpid kcall ret: %lld, jailbreakd pid: %d\n", kcall_ret, pid_by_name("jailbreakd"));
    
    //testing 10 = load trustcache from file
    char* execPath = [NSString stringWithFormat:@"%@/unsigned/unsignedhelloworld", NSBundle.mainBundle.bundlePath].UTF8String;
    printf("execPath: %s\n", execPath);
    chmod(execPath, 0755);
    message = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(message, "id", JBD_MSG_PROCESS_BINARY);
    xpc_dictionary_set_string(message, "filePath", execPath);
    reply = sendJBDMessage(message);
    if(!reply) {
        printf("Failed to get reply from jailbreakd\n");
        return;
    }
    ret = xpc_dictionary_get_uint64(reply, "ret");
    printf("JBD_MSG_PROCESS_BINARY ret: 0x%llx\n", ret);
    util_runCommand(execPath, NULL, NULL);

    //kill
    launch("/var/jb/usr/bin/killall", "-9", "jailbreakd", NULL, NULL, NULL, NULL, NULL);
    usleep(10000);
    launch("/var/jb/bin/launchctl", "unload", "/var/jb/basebin/LaunchDaemons/kr.h4ck.jailbreakd.plist", NULL, NULL, NULL, NULL, NULL);
}
