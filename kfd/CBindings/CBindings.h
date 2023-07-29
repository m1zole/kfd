//
//  CBindings.h
//  kexploitd
//
//  Created by Linus Henze.
//  Copyright © 2022 Pinauten GmbH. All rights reserved.
//

#ifndef CBindings_h
#define CBindings_h

#include <spawn.h>
#include <fcntl.h>
#import <Foundation/Foundation.h>
#include <device/device_types.h>

#include "posix_spawn.h"
#include "th_state.h"
//#include "libjailbreak.h"
//#include "wifi.h"

extern int decompress_tar_zstd(const char* src_file_path, const char* dst_file_path);
extern int loadEmbeddedSignature(NSString* filePath);
uint64_t getPCIMemorySize(void);
NSString *getBootManifestHash(void);

// Also define some IOKit stuff...
extern const mach_port_t kIOMainPortDefault;

extern mach_port_t IORegistryEntryFromPath(mach_port_t mainPort, const io_string_t __nonnull path);
extern CFTypeRef __nonnull IORegistryEntryCreateCFProperty(mach_port_t entry, CFStringRef __nonnull key, CFAllocatorRef __nullable allocator, uint32_t options);
extern kern_return_t IOObjectRelease(mach_port_t object);

extern uint64_t reboot3(uint64_t how, uint64_t unk);

#endif /* CBindings_h */