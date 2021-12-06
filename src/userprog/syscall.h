#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

/* [EDITED_Lab2_argument_passing] */
void is_userArea(void *uaddr);
void read_arg(void *esp, int *arg, int num_arg_item);

/* [EDITED_Lab2_file_descriptor] */ // check
struct lock lock_file;
void sys_exit(int exit_status);
void sys_close(int num_fd);

#endif /* userprog/syscall.h */