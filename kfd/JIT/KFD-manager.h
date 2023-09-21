//
//  KFD-manager.h
//  kfd
//
//  Created by m1zole on 2023/09/16.
//

#ifndef KFD_manager_h
#define KFD_manager_h

uint64_t mountusrDir(void);
uint64_t mountselectedDir(NSString* path);
void unmountselectedDir(uint64_t orig_to_v_data, NSString* mntPath);
void prepare(void);
void do_tasks(void);

#endif /* KFD_manager_h */
