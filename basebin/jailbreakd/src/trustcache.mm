#import "trustcache.h"
#import "JBDTCPage.h"
#import "boot_info.h"
#import "kernel/krw.h"
#import "kernel/proc.h"
#import "macho.h"
#import "signatures.h"

int tcentryComparator(const void *vp1, const void *vp2) {
  trustcache_entry *tc1 = (trustcache_entry *)vp1;
  trustcache_entry *tc2 = (trustcache_entry *)vp2;
  return memcmp(tc1->hash, tc2->hash, CS_CDHASH_LEN);
}

JBDTCPage *trustCacheFindFreePage(void) {
  // Find page that has slots left
  for (JBDTCPage *page in gTCPages) {
    @autoreleasepool {
      if (page.amountOfSlotsLeft > 0) {
        return page;
      }
    }
  }

  // No page found, allocate new one
  return [[JBDTCPage alloc] initAllocateAndLink];
}

BOOL isCdHashInTrustCache(NSData *cdHash) {
  kern_return_t kr;

  CFMutableDictionaryRef amfiServiceDict =
      IOServiceMatching("AppleMobileFileIntegrity");
  if (amfiServiceDict) {
    io_connect_t connect;
    io_service_t amfiService =
        IOServiceGetMatchingService(kIOMainPortDefault, amfiServiceDict);
    kr = IOServiceOpen(amfiService, mach_task_self(), 0, &connect);
    if (kr != KERN_SUCCESS) {
      NSLog(@"[jailbreakd] Failed to open amfi service %d %s", kr,
            mach_error_string(kr));
      return -2;
    }

    uint64_t includeLoadedTC = YES;
    kr = IOConnectCallMethod(
        connect, AMFI_IS_CD_HASH_IN_TRUST_CACHE, &includeLoadedTC, 1,
        CFDataGetBytePtr((__bridge CFDataRef)cdHash),
        CFDataGetLength((__bridge CFDataRef)cdHash), 0, 0, 0, 0);
    NSLog(@"[jailbreakd] Is %s in TrustCache? %s",
          cdHash.description.UTF8String, kr == 0 ? "Yes" : "No");

    IOServiceClose(connect);
    return kr == 0;
  }

  return NO;
}

BOOL trustCacheListAdd(uint64_t trustCacheKaddr) {
  NSLog(@"[jailbreakd] trustCacheListAdd: trustCacheKaddr: 0x%llx\n",
        trustCacheKaddr);
  if (!trustCacheKaddr)
    return NO;

  uint64_t pmap_image4_trust_caches = bootInfo_getSlidUInt64(@"off_trustcache");
  uint64_t curTc = kread64(pmap_image4_trust_caches);
  if (curTc == 0) {
    kwrite64(pmap_image4_trust_caches, trustCacheKaddr);
  } else {
    uint64_t prevTc = 0;
    while (curTc != 0) {
      prevTc = curTc;
      curTc = kread64(curTc);
    }
    kwrite64(prevTc, trustCacheKaddr);
  }

  return YES;
}

BOOL trustCacheListRemove(uint64_t trustCacheKaddr) {
  if (!trustCacheKaddr)
    return NO;

  uint64_t nextPtr =
      kread64(trustCacheKaddr + offsetof(trustcache_page, nextPtr));

  uint64_t pmap_image4_trust_caches = bootInfo_getSlidUInt64(@"off_trustcache");
  uint64_t curTc = kread64(pmap_image4_trust_caches);
  if (curTc == 0) {
    NSLog(@"[jailbreakd] WARNING: Tried to unlink trust cache page 0x%llX but "
           "pmap_image4_trust_caches points to 0x0",
          trustCacheKaddr);
    return NO;
  } else if (curTc == trustCacheKaddr) {
    kwrite64(pmap_image4_trust_caches, nextPtr);
  } else {
    uint64_t prevTc = 0;
    while (curTc != trustCacheKaddr) {
      if (curTc == 0) {
        NSLog(@"[jailbreakd] WARNING: Hit end of trust cache chain while "
              @"trying to "
               "unlink trust cache page 0x%llX",
              trustCacheKaddr);
        return NO;
      }
      prevTc = curTc;
      curTc = kread64(curTc);
    }
    kwrite64(prevTc, nextPtr);
  }
  return YES;
}

uint64_t staticTrustCacheUploadFile(trustcache_file *fileToUpload,
                                    size_t fileSize, size_t *outMapSize) {
  if (fileSize < sizeof(trustcache_file)) {
    NSLog(@"[jailbreakd] attempted to load a trustcache file that's too "
          @"small.\n");
    return 0;
  }

  size_t expectedSize =
      sizeof(trustcache_file) + fileToUpload->length * sizeof(trustcache_entry);
  if (expectedSize != fileSize) {
    NSLog(@"[jailbreakd] attempted to load a trustcache file with an invalid "
          @"size (0x%zX vs 0x%zX)\n",
          expectedSize, fileSize);
    return 0;
  }

  uint64_t mapSize = sizeof(trustcache_page) + fileSize;

  uint64_t mapKaddr = kalloc(mapSize);
  if (!mapKaddr) {
    NSLog(@"[jailbreakd] failed to allocate memory for trust cache file with "
          @"size %zX\n",
          fileSize);
    return 0;
  }

  if (outMapSize)
    *outMapSize = mapSize;

  uint64_t mapSelfPtrPtr = mapKaddr + offsetof(trustcache_page, selfPtr);
  uint64_t mapSelfPtr = mapKaddr + offsetof(trustcache_page, file);

  kwrite64(mapSelfPtrPtr, mapSelfPtr);

  kwritebuf(mapSelfPtr, fileToUpload, fileSize);

  trustCacheListAdd(mapKaddr);
  return mapKaddr;
}

void dynamicTrustCacheUploadCDHashesFromArray(NSArray *cdHashArray) {
  __block JBDTCPage *mappedInPage = nil;
  for (NSData *cdHash in cdHashArray) {
    @autoreleasepool {
      if (!mappedInPage || mappedInPage.amountOfSlotsLeft == 0) {
        // If there is still a page mapped, map it out now
        if (mappedInPage) {
          [mappedInPage sort];
        }

        mappedInPage = trustCacheFindFreePage();
      }

      trustcache_entry entry;
      memcpy(&entry.hash, cdHash.bytes, CS_CDHASH_LEN);
      entry.hash_type = 0x2;
      entry.flags = 0x0;
      NSLog(@"[jailbreakd] [dynamicTrustCacheUploadCDHashesFromArray] "
            @"uploading %s",
            cdHash.description.UTF8String);
      [mappedInPage addEntry:entry];
    }
  }

  if (mappedInPage) {
    [mappedInPage sort];
  }
}

int processBinary(NSString *binaryPath) {
  if (!binaryPath)
    return 0;
  if (![[NSFileManager defaultManager] fileExistsAtPath:binaryPath])
    return 0;

  int ret = 0;

  uint64_t selfproc = proc_of_pid(getpid());

  FILE *machoFile = fopen(binaryPath.fileSystemRepresentation, "rb");
  if (!machoFile)
    return 1;

  if (machoFile) {
    int fd = fileno(machoFile);

    bool isMacho = NO;
    bool isLibrary = NO;
    machoGetInfo(machoFile, &isMacho, &isLibrary);

    if (isMacho) {
      int64_t bestArchCandidate = machoFindBestArch(machoFile);
      if (bestArchCandidate >= 0) {
        uint32_t bestArch = bestArchCandidate;
        NSMutableArray *nonTrustCachedCDHashes = [NSMutableArray new];

        void (^tcCheckBlock)(NSString *) = ^(NSString *dependencyPath) {
          if (dependencyPath) {
            NSURL *dependencyURL = [NSURL fileURLWithPath:dependencyPath];
            NSData *cdHash = nil;
            BOOL isAdhocSigned = NO;
            evaluateSignature(dependencyURL, &cdHash, &isAdhocSigned);
            if (isAdhocSigned) {
              if (!isCdHashInTrustCache(cdHash)) {
                [nonTrustCachedCDHashes addObject:cdHash];
              }
            }
          }
        };

        tcCheckBlock(binaryPath);

        machoEnumerateDependencies(machoFile, bestArch, binaryPath,
                                   tcCheckBlock);

        dynamicTrustCacheUploadCDHashesFromArray(nonTrustCachedCDHashes);
      } else {
        ret = 3;
      }
    } else {
      ret = 2;
    }
    fclose(machoFile);
  } else {
    ret = 1;
  }

  return ret;
}