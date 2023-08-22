#import <Foundation/Foundation.h>

int reboot3(uint64_t flags, ...);
#define RB2_USERREBOOT (0x2000000000000000llu)

extern NSDictionary* gBootInfo;
uint64_t bootInfo_getUInt64(NSString* name);
uint64_t bootInfo_getSlidUInt64(NSString* name);
NSData* bootInfo_getData(NSString* name);

extern uint64_t gSelfProc;
extern uint64_t gSelfTask;

void primitivesInitializedCallback(void);

typedef enum {
    JBD_MSG_KRW_READY = 1,
    JBD_MSG_KERNINFO = 2,
    JBD_MSG_KREAD32 = 3,
    JBD_MSG_KREAD64 = 4,
    JBD_MSG_KWRITE32 = 5,
    JBD_MSG_KWRITE64 = 6,
    JBD_MSG_KALLOC = 7,
    JBD_MSG_KFREE = 8,
} JBD_MESSAGE_ID;