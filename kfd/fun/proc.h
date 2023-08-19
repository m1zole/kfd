//
//  proc.h
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/19.
//

#ifndef proc_h
#define proc_h

#include <stdio.h>

pid_t pid_by_name(char* nm);
uint64_t proc_by_name(char* nm);
uint64_t proc_of_pid(pid_t pid);

#endif /* proc_h */
