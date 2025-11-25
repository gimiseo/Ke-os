#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"

void syscall_init (void);
extern struct lock filesys_lock;
typedef int pid_t;
struct file *
fd_to_file_for_find(struct thread * curr, int fd);

#endif /* userprog/syscall.h */
