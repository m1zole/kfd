//
//  bootstrap.c
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/21.
//

#import "bootstrap.h"
#import "utils.h"
#import "escalate.h"
#import "proc.h"
#import "vnode.h"
#import "boot_info.h"
#import "offsets.h"

#import <stdbool.h>
#import <Foundation/Foundation.h>
#import <sys/stat.h>


typedef UInt32        IOOptionBits;
#define IO_OBJECT_NULL ((io_object_t)0)
typedef mach_port_t io_object_t;
typedef io_object_t io_registry_entry_t;
extern const mach_port_t kIOMainPortDefault;
typedef char io_string_t[512];

kern_return_t
IOObjectRelease(io_object_t object );

io_registry_entry_t
IORegistryEntryFromPath(mach_port_t, const io_string_t);

CFTypeRef
IORegistryEntryCreateCFProperty(io_registry_entry_t entry, CFStringRef key, CFAllocatorRef allocator, IOOptionBits options);

extern char **environ;

int remountPrebootPartition(bool writable) {
    if(writable) {
        launch("/sbin/mount", "-u", "-w", "/private/preboot", NULL, NULL, NULL, NULL);
    } else {
        launch("/sbin/mount", "-u", "/private/preboot", NULL, NULL, NULL, NULL, NULL);
    }
    return 0;
}

char* getBootManifestHash(void) {
    io_registry_entry_t registryEntry = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/chosen");
    if (registryEntry == IO_OBJECT_NULL) {
        return NULL;
    }
    CFDataRef bootManifestHash = IORegistryEntryCreateCFProperty(registryEntry, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, kNilOptions);
    if(!bootManifestHash) {
        return NULL;
    }
    
    IOObjectRelease(registryEntry);
    
    CFIndex length = CFDataGetLength(bootManifestHash) * 2 + 1;
    char *manifestHash = (char*)calloc(length, sizeof(char));
    
    int i = 0;
    for (i = 0; i<(int)CFDataGetLength(bootManifestHash); i++) {
        sprintf(manifestHash+i*2, "%02X", CFDataGetBytePtr(bootManifestHash)[i]);
    }
    manifestHash[i*2] = 0;
    
    CFRelease(bootManifestHash);
    
    return manifestHash;
}


int UUIDPathPermissionFixup(void) {
    NSString *UUIDPath = [NSString stringWithFormat:@"%s%s", "/private/preboot/", getBootManifestHash()];
//    printf("UUIDPath: %s\n", UUIDPath.UTF8String);
    
    struct stat UUIDPathStat;
    if (stat(UUIDPath.UTF8String, &UUIDPathStat) != 0) {
        printf("Failed to stat %s\n", UUIDPath.UTF8String);
        return -1;
    }
    
    uid_t curOwnerID = UUIDPathStat.st_uid;
    gid_t curGroupID = UUIDPathStat.st_gid;
    if (curOwnerID != 0 || curGroupID != 0) {
        if (chown(UUIDPath.UTF8String, 0, 0) != 0) {
            printf("Failed to chown 0:0 %s\n", UUIDPath.UTF8String);
            return -1;
        }
    }
    
    mode_t curPermissions = UUIDPathStat.st_mode & S_IRWXU;
    if (curPermissions != 0755) {
        if (chmod(UUIDPath.UTF8String, 0755) != 0) {
            printf("Failed to chmod 755 %s\n", UUIDPath.UTF8String);
            return -1;
        }
    }
    
    return 0;
}

void wipeSymlink(NSString *path) {
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSError *error = nil;
    
    NSDictionary *attributes = [fileManager attributesOfItemAtPath:path error:&error];
    if (!error) {
        NSString *fileType = attributes[NSFileType];
        if ([fileType isEqualToString:NSFileTypeSymbolicLink]) {
            [fileManager removeItemAtPath:path error:&error];
            if (!error) {
                printf("Deleted symlink at %s\n", path.UTF8String);
            }
        } else {
            //[Logger print:[NSString stringWithFormat:@"Wanted to delete symlink at %@, but it is not a symlink", path]];
        }
    } else {
        //[Logger print:[NSString stringWithFormat:@"Wanted to delete symlink at %@, error occurred: %@, but we ignore it", path, error]];
    }
}

char* locateExistingFakeRoot(void) {
    NSString *bootManifestHash = [NSString stringWithUTF8String:getBootManifestHash()];
    if (!bootManifestHash) {
        return NULL;
    }
    
    NSString *ppPath = [NSString stringWithFormat:@"/private/preboot/%@", bootManifestHash];
    NSError *error = nil;
    NSArray<NSString *> *candidateURLs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:ppPath error:&error];
    if (!error) {
        for (NSString *candidatePath in candidateURLs) {
            if ([candidatePath.lastPathComponent hasPrefix:@"jb-"]) {
                char *ret = malloc(1024);
                strcpy(ret, [NSString stringWithFormat:@"%@/%@", ppPath, candidatePath].UTF8String);
                
                return ret;
            }
        }
    }
    return NULL;
}

char* generateFakeRootPath(void) {
    NSString *letters = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    NSMutableString *result = [NSMutableString stringWithCapacity:6];
    
    for (NSUInteger i = 0; i < 6; i++) {
        NSUInteger randomIndex = arc4random_uniform((uint32_t)[letters length]);
        unichar randomCharacter = [letters characterAtIndex:randomIndex];
        [result appendFormat:@"%C", randomCharacter];
    }
    
    NSString *bootManifestHash = [NSString stringWithUTF8String:getBootManifestHash()];
    if (!bootManifestHash) {
        return NULL;
    }
    
    NSString *fakeRootPath = [NSString stringWithFormat:@"/private/preboot/%@/jb-%@", bootManifestHash, result];
    return fakeRootPath.UTF8String;
}

void createSymbolicLinkAtPath_withDestinationPath(char* path, char* pathContent) {
    NSString *path_ns = [NSString stringWithUTF8String:path];
    NSString *pathContent_ns = [NSString stringWithUTF8String:pathContent];
    NSArray<NSString *> *components = [path_ns componentsSeparatedByString:@"/"];
    NSString *directoryPath = [[components subarrayWithRange:NSMakeRange(0, components.count - 1)] componentsJoinedByString:@"/"];
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:directoryPath]) {
        NSError *error = nil;
        [fileManager createDirectoryAtPath:directoryPath withIntermediateDirectories:YES attributes:nil error:&error];
        if (error) {
            NSLog(@"Failed to create directory. Error: %@", error);
            return;
        }
    }
    
    NSError *error = nil;
    [fileManager createSymbolicLinkAtPath:path_ns withDestinationPath:pathContent_ns error:&error];
    if (error) {
        NSLog(@"Failed to create symbolic link. Error: %@", error);
    }
}

int untar(char* tarPath, char* target) {
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    
    NSString *tarBinary = [NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/binaries/tar"];
    chmod(tarBinary.UTF8String, 0755);
    
    pid_t pid;
    const char* args[] = {"tar", "--preserve-permissions", "-xkf", tarPath, "-C", target, NULL};
    
    int status = posix_spawn(&pid, tarBinary.UTF8String, NULL, &attr, (char **)&args, environ);
    if(status == 0) {
        rootify(pid);
        kill(pid, SIGCONT);
        
        if(waitpid(pid, &status, 0) == -1) {
            printf("waitpid error\n");
        }
        
    }
    printf("untar posix_spawn status: %d\n", status);
    
    return 0;
}

void patchBaseBinLaunchDaemonPlist(NSString *plistPath)
{
    NSMutableDictionary *plistDict = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    if (plistDict) {
        NSMutableArray *programArguments = ((NSArray *)plistDict[@"ProgramArguments"]).mutableCopy;
        if (programArguments.count >= 1) {
            NSString *pathBefore = programArguments[0];
            if (![pathBefore hasPrefix:@"/private/preboot"]) {
                programArguments[0] = prebootPath(pathBefore);
                plistDict[@"ProgramArguments"] = programArguments.copy;
                [plistDict writeToFile:plistPath atomically:YES];
            }
        }
    }
}

void patchBaseBinLaunchDaemonPlists(void)
{
    NSURL *launchDaemonURL = [NSURL fileURLWithPath:prebootPath(@"basebin/LaunchDaemons") isDirectory:YES];
    NSArray<NSURL *> *launchDaemonPlistURLs = [[NSFileManager defaultManager] contentsOfDirectoryAtURL:launchDaemonURL includingPropertiesForKeys:nil options:0 error:nil];
    for (NSURL *launchDaemonPlistURL in launchDaemonPlistURLs) {
        patchBaseBinLaunchDaemonPlist(launchDaemonPlistURL.path);
    }
}

int extractBootstrap(void) {
    char* jbPath = "/var/jb";
    NSString *jbPath_ns = [NSString stringWithUTF8String:jbPath];
    remountPrebootPartition(true);
    
    while(access([NSString stringWithFormat:@"/private/preboot/%s", getBootManifestHash()].UTF8String, R_OK | W_OK) != 0) {;};
    
    if(UUIDPathPermissionFixup() != 0) {
        return -1;
    }
    wipeSymlink(jbPath_ns);
    if(access(jbPath, F_OK) == 0) {
        [[NSFileManager defaultManager] removeItemAtPath:jbPath_ns error:nil];
    }
    
    char* fakeRootPath = locateExistingFakeRoot();
//    printf("fakeRootPath: %s\n", fakeRootPath);
    
    if(fakeRootPath == NULL) {
        fakeRootPath = generateFakeRootPath();
        [[NSFileManager defaultManager] createDirectoryAtPath:[NSString stringWithUTF8String:fakeRootPath] withIntermediateDirectories:YES attributes:nil error:nil];
    }
    
    bool bootstrapNeedsExtract = false;
    NSString* procursusPath = [NSString stringWithFormat:@"%s%s", fakeRootPath, "/procursus"];
    NSString* installedPath = [NSString stringWithFormat:@"%@%s", procursusPath, "/.installed_kfund"];
    NSString* prereleasePath = [NSString stringWithFormat:@"%@%s", procursusPath, "/.used_kfund_prerelease"];
    
    if(access(procursusPath.UTF8String, F_OK) == 0) {
        if(access(installedPath.UTF8String, F_OK) != 0) {
            printf("Wiping existing bootstrap because installed file not found\n");
            [[NSFileManager defaultManager] removeItemAtPath:procursusPath error:nil];
        }
        if(access(prereleasePath.UTF8String, F_OK) == 0) {
            printf("Wiping existing bootstrap because pre release\n");
            [[NSFileManager defaultManager] removeItemAtPath:procursusPath error:nil];
        }
    }
    
    if(access(procursusPath.UTF8String, F_OK) != 0) {
        [[NSFileManager defaultManager] createDirectoryAtPath:procursusPath withIntermediateDirectories:YES attributes:nil error:nil];
        bootstrapNeedsExtract = true;
    }
    
    // Update basebin (should be done every rejailbreak)
    NSString *basebinPath = [NSString stringWithFormat:@"%@/basebin", procursusPath];
    if(access(basebinPath.UTF8String, F_OK) == 0) {
        [[NSFileManager defaultManager] removeItemAtPath:basebinPath error:nil];
    }
//    let basebinTarPath = Bundle.main.bundlePath + "/basebin.tar"
//    let basebinPath = procursusPath + "/basebin"  //DONE
//    if FileManager.default.fileExists(atPath: basebinPath) {//DONE
//        try FileManager.default.removeItem(atPath: basebinPath)//DONE
//    }//DONE
//    let untarRet = untar(tarPath: basebinTarPath, target: procursusPath)
//    if untarRet != 0 {
//        throw BootstrapError.custom(String(format:"Failed to untar Basebin: \(String(describing: untarRet))"))
//    }
    printf("mkdir ret: %d\n", mkdir(basebinPath.UTF8String, 0755));
    
//    printf("jbPath: %s, procursusPath: %s\n", jbPath, procursusPath.UTF8String);
    createSymbolicLinkAtPath_withDestinationPath(jbPath, procursusPath.UTF8String);
    
    if(bootstrapNeedsExtract) {
        NSString *bootstrapPath = [NSString stringWithFormat:@"%@%s", NSBundle.mainBundle.bundlePath, "/iosbinpack/bootstrap-iphoneos-arm64.tar"];
        untar(bootstrapPath.UTF8String, "/");

        [@"" writeToFile:installedPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    
    NSString *defaultSources = @"\
    Types: deb\n\
    URIs: https://repo.chariz.com/\n\
    Suites: ./\n\
    Components:\n\
    \n\
    Types: deb\n\
    URIs: https://havoc.app/\n\
    Suites: ./\n\
    Components:\n\
    \n\
    Types: deb\n\
    URIs: http://apt.thebigboss.org/repofiles/cydia/\n\
    Suites: stable\n\
    Components: main\n\
    \n\
    Types: deb\n\
    URIs: https://ellekit.space/\n\
    Suites: ./\n\
    Components:\n";
    
    [defaultSources writeToFile:@"/var/jb/etc/apt/sources.list.d/default.sources" atomically:NO encoding:NSUTF8StringEncoding error:nil];
    
    // Create basebin symlinks if they don't exist
//    if !fileOrSymlinkExists(atPath: "/var/jb/usr/bin/opainject") {
//        try createSymbolicLink(atPath: "/var/jb/usr/bin/opainject", withDestinationPath: procursusPath + "/basebin/opainject")
//    }
//    if !fileOrSymlinkExists(atPath: "/var/jb/usr/bin/jbctl") {
//        try createSymbolicLink(atPath: "/var/jb/usr/bin/jbctl", withDestinationPath: procursusPath + "/basebin/jbctl")
//    }
//    if !fileOrSymlinkExists(atPath: "/var/jb/usr/lib/libjailbreak.dylib") {
//        try createSymbolicLink(atPath: "/var/jb/usr/lib/libjailbreak.dylib", withDestinationPath: procursusPath + "/basebin/libjailbreak.dylib")
//    }
//    if !fileOrSymlinkExists(atPath: "/var/jb/usr/lib/libfilecom.dylib") {
//        try createSymbolicLink(atPath: "/var/jb/usr/lib/libfilecom.dylib", withDestinationPath: procursusPath + "/basebin/libfilecom.dylib")
//    }
    //1. Copy kr.h4ck.jailbreak.plist to LaunchDaemons
    if(access("/var/jb/basebin/LaunchDaemons", F_OK) != 0)
        mkdir("/var/jb/basebin/LaunchDaemons", 0755);
    [[NSFileManager defaultManager] removeItemAtPath:@"/var/jb/basebin/LaunchDaemons/kr.h4ck.jailbreakd.plist" error:nil];
    [[NSFileManager defaultManager] copyItemAtPath:[NSString stringWithFormat:@"%@/binaries/kr.h4ck.jailbreakd.plist", NSBundle.mainBundle.bundlePath] toPath:@"/var/jb/basebin/LaunchDaemons/kr.h4ck.jailbreakd.plist" error:nil];
    chown("/var/jb/basebin/LaunchDaemons/kr.h4ck.jailbreakd.plist", 0, 0);
    patchBaseBinLaunchDaemonPlist(@"/var/jb/basebin/LaunchDaemons/kr.h4ck.jailbreakd.plist");
    
    //2. Copy jailbreakd to basebin
    [[NSFileManager defaultManager] removeItemAtPath:@"/var/jb/basebin/jailbreakd" error:nil];
    [[NSFileManager defaultManager] copyItemAtPath:[NSString stringWithFormat:@"%@/binaries/jailbreakd", NSBundle.mainBundle.bundlePath] toPath:@"/var/jb/basebin/jailbreakd" error:nil];
    chown("/var/jb/basebin/jailbreakd", 0, 0);
    chmod("/var/jb/basebin/jailbreakd", 0755);
    //3. Copy jbinit to basebin
    [[NSFileManager defaultManager] removeItemAtPath:@"/var/jb/basebin/jbinit" error:nil];
    [[NSFileManager defaultManager] copyItemAtPath:[NSString stringWithFormat:@"%@/binaries/jbinit", NSBundle.mainBundle.bundlePath] toPath:@"/var/jb/basebin/jbinit" error:nil];
    chown("/var/jb/basebin/jbinit", 0, 0);
    chmod("/var/jb/basebin/jbinit", 0755);
    //4. Copy launchdhook.dylib to basebin
    [[NSFileManager defaultManager] removeItemAtPath:@"/var/jb/basebin/launchdhook.dylib" error:nil];
    [[NSFileManager defaultManager] copyItemAtPath:[NSString stringWithFormat:@"%@/binaries/launchdhook.dylib", NSBundle.mainBundle.bundlePath] toPath:@"/var/jb/basebin/launchdhook.dylib" error:nil];
    chown("/var/jb/basebin/launchdhook.dylib", 0, 0);
    chmod("/var/jb/basebin/launchdhook.dylib", 0755);
    //5. Copy opainject to basebin
    [[NSFileManager defaultManager] removeItemAtPath:@"/var/jb/basebin/opainject" error:nil];
    [[NSFileManager defaultManager] copyItemAtPath:[NSString stringWithFormat:@"%@/binaries/opainject", NSBundle.mainBundle.bundlePath] toPath:@"/var/jb/basebin/opainject" error:nil];
    chown("/var/jb/basebin/opainject", 0, 0);
    chmod("/var/jb/basebin/opainject", 0755);
    
    // Create preferences directory if it does not exist
    NSFileManager *fileManager = [NSFileManager defaultManager];
    
    if (![fileManager fileExistsAtPath:@"/var/jb/var/mobile/Library/Preferences"]) {
        NSDictionary *attributes = @{NSFilePosixPermissions: @(0755), NSFileOwnerAccountID: @(501), NSFileGroupOwnerAccountID: @(501)};
        
        [fileManager createDirectoryAtPath:@"/var/jb/var/mobile/Library/Preferences" withIntermediateDirectories:YES attributes:attributes error:nil];
    }
    

    // Write boot info from cache to disk
    NSMutableDictionary *cachedBootInfo = [NSMutableDictionary dictionary];
    NSString *bootInfoPath = @"/var/jb/basebin/boot_info.plist";
    BOOL success = [cachedBootInfo writeToFile:bootInfoPath atomically:YES];
    if (!success) {
        printf("[-] Failed create boot_info.plist.\n");
        return -1;
    }
    
    //Save some boot_info
    bootInfo_setObject(@"off_kalloc_data_external", @(off_kalloc_data_external));
    bootInfo_setObject(@"off_kfree_data_external", @(off_kfree_data_external));
    bootInfo_setObject(@"off_add_x0_x0_0x40_ret", @(off_add_x0_x0_0x40_ret));
    bootInfo_setObject(@"off_empty_kdata_page", @(off_empty_kdata_page));
    bootInfo_setObject(@"off_trustcache", @(off_trustcache));
    bootInfo_setObject(@"off_gphysbase", @(off_gphysbase));
    bootInfo_setObject(@"off_gphyssize", @(off_gphyssize));
    bootInfo_setObject(@"off_pmap_enter_options_addr", @(off_pmap_enter_options_addr));
    bootInfo_setObject(@"off_allproc", @(off_allproc));
    NSDictionary *tmp_kfd_arm64 = [NSDictionary dictionaryWithContentsOfFile:@"/tmp/kfd-arm64.plist"];
    bootInfo_setObject(@"kcall_fake_vtable_allocations", @([tmp_kfd_arm64[@"kcall_fake_vtable_allocations"] unsignedLongLongValue]));
    bootInfo_setObject(@"kcall_fake_client_allocations", @([tmp_kfd_arm64[@"kcall_fake_client_allocations"] unsignedLongLongValue]));
    
    return 0;
}
