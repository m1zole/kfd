//
//  fun.h
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/07/25.
//

#ifndef fun_h
#define fun_h

#include <stdio.h>

void do_fun(char** enabledTweaks, int numTweaks);
uint64_t fun_nvram_dump(void);
void backboard_respring(void);
#endif /* fun_h */
