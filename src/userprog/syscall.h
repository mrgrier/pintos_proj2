#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "filesys/file.h"

void syscall_init (void);

int add_file(struct file* f);
struct file* get_file(int fd);
void close_file(int fd);
void close_all_files(void);

#endif /* userprog/syscall.h */
