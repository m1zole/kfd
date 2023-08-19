//
//  trustcache.m
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/19.
//

#import <Foundation/Foundation.h>
#import "trustcache.h"
#import "krw.h"
#import "offsets.h"

BOOL trustCacheListAdd(uint64_t trustCacheKaddr)
{
    if (!trustCacheKaddr) return NO;

    uint64_t pmap_image4_trust_caches = off_trustcache + get_kslide();
    uint64_t curTc = kread64(pmap_image4_trust_caches);
    if(curTc == 0) {
        kwrite64(pmap_image4_trust_caches, trustCacheKaddr);
    }
    else {
        uint64_t prevTc = 0;
        while (curTc != 0)
        {
            prevTc = curTc;
            curTc = kread64(curTc);
        }
        kwrite64(prevTc, trustCacheKaddr);
    }

    return YES;
}


uint64_t staticTrustCacheUploadFile(trustcache_file *fileToUpload, size_t fileSize, size_t *outMapSize)
{
    if (fileSize < sizeof(trustcache_file)) {
        printf("attempted to load a trustcache file that's too small.\n");
        return 0;
    }

    size_t expectedSize = sizeof(trustcache_file) + fileToUpload->length * sizeof(trustcache_entry);
    if (expectedSize != fileSize) {
        printf("attempted to load a trustcache file with an invalid size (0x%zX vs 0x%zX)\n", expectedSize, fileSize);
        return 0;
    }

    uint64_t mapSize = sizeof(trustcache_page) + fileSize;

    uint64_t mapKaddr = kalloc(mapSize);
    if (!mapKaddr) {
        printf("failed to allocate memory for trust cache file with size %zX\n", fileSize);
        return 0;
    }

    if (outMapSize) *outMapSize = mapSize;

    uint64_t mapSelfPtrPtr = mapKaddr + offsetof(trustcache_page, selfPtr);
    uint64_t mapSelfPtr = mapKaddr + offsetof(trustcache_page, file);

    kwrite64(mapSelfPtrPtr, mapSelfPtr);
    printf("fileSize: %d\n", fileSize);
    
//    do_kwrite(mapSelfPtr, fileToUpload, fileSize);
    kwritebuf(mapSelfPtr, fileToUpload, fileSize);
    
    
    trustCacheListAdd(mapKaddr);
    return mapKaddr;
}

uint64_t staticTrustCacheUploadFileAtPath(NSString *filePath, size_t *outMapSize)
{
    if (!filePath) return 0;
    NSData *tcData = [NSData dataWithContentsOfFile:filePath];
    if (!tcData) return 0;
    return staticTrustCacheUploadFile((trustcache_file *)tcData.bytes, tcData.length, outMapSize);
}
