#ifndef helpers_h
#define helpers_h

char* kfd_get_temp_file_path(void);
void kfd_test_nsexpressions(void);
char* kfd_set_up_tmp_file(void);

void kfd_xpc_crasher(char* service_name);

void restartBackboard(void);
void restartFrontboard(void);


#define ROUND_DOWN_PAGE(val) (val & ~(PAGE_SIZE - 1ULL))

#endif /* helpers_h */
