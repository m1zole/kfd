//
//  sandbox.h
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/08/19.
//

#ifndef sandbox_h
#define sandbox_h

char *sandbox_extension_issue_file(const char *extension_class, const char *path, uint32_t flags);

uint64_t unsandbox(pid_t pid);
BOOL sandbox(pid_t pid, uint64_t sb);

int64_t sandbox_extension_consume(const char *extension_token);
char* token_by_sandbox_extension_issue_file(const char *extension_class, const char *path, uint32_t flags);

#endif /* sandbox_h */
