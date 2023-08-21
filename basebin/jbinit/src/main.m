#import <Foundation/Foundation.h>
#import <spawn.h>
#import "launchctl.h"
#import "boot_info.h"

int main(int argc, char* argv[])
{
	launchctl_load(prebootPath(@"basebin/LaunchDaemons/kr.h4ck.jailbreakd.plist").fileSystemRepresentation, false);

	return 0;
}