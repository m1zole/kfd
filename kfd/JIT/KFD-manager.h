//
//  KFD-manager.h
//  kfd
//
//  Created by m1zole on 2023/09/16.
//

#ifndef KFD_manager_h
#define KFD_manager_h

uint64_t mountAppsDir(void);
uint64_t mountusrDir(void);
uint64_t mountmobileDir(NSString* path);
void unmountAppsDir(uint64_t orig_to_v_data);
void containersdir(void);
void prepare(void);

#endif /* KFD_manager_h */
