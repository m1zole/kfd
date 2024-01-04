//
//  utils.h
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/07/30.
//

#include <stdio.h>
#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>

void HexDump(uint64_t addr, size_t size);
bool sandbox_escape_can_i_access_file(char* path, int mode);
