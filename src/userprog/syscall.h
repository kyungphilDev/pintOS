#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

/* [EDITED_Lab2_argument_passing] */
void is_userArea(void *uaddr);
void read_arg(void *esp, int *arg, int num_arg_item);
void sys_exit(int exit_status);
#endif /* userprog/syscall.h */