#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
/* [ADDED_Lab2_system_call] */
#include <devices/shutdown.h>
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "threads/synch.h"
#define PHYS_BASE 0xc0000000;

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
  int MAX_ARG = 7;
  int argv[MAX_ARG];
  void *esp = f->esp; // user's stack pointer
  /* check esp is valid user area pointer */
  is_userArea(esp);
  int syscall_code = *(int *)esp;
  // printf("\n kyungphil_syscall_code: %d\n", syscall_code);

  /* sys call handler */
  switch (syscall_code)
  {
  case SYS_HALT:
  {
    shutdown_power_off();
    break;
  }
  case SYS_EXIT:
  {
    read_arg(esp, argv, 1); // read exit status from args
    int exit_status = argv[0];
    sys_exit(argv[0]);
    break;
  }
  case SYS_WRITE:
  {
    f->eax = write((int)*(uint32_t *)(f->esp + 20), (void *)*(uint32_t *)(f->esp + 24), (unsigned)*((uint32_t *)(f->esp + 28)));
    break;
  }
  // case SYS_CREATE:
  // {
  //   read_arg(esp, argv, 2); // read create args
  //   is_userArea((void *)argv[0]);
  //   // set return value of function
  //   char *filename = (char *)argv[0];
  //   unsigned size_file = argv[1];
  //   bool ret = filesys_create(filename, size_file);
  //   f->eax = ret;
  //   break;
  // }
  // case SYS_REMOVE:
  // {
  //   read_arg(esp, argv, 1); // read remove args
  //   is_userArea((void *)argv[0]);
  //   char *filename = (char *)argv[0];
  //   bool ret = filesys_remove(filename);
  //   f->eax = ret;
  //   break;
  // }
  case SYS_EXEC:
  {
    printf("\n kyungphil_syscall\n");
    read_arg(esp, argv, 1);
    is_userArea((void *)argv[0]);
    // f->eax = -1; // todo
    /* wait for child */
    char *exec_file = (char *)argv[0];
    tid_t pid = process_execute(exec_file);
    // struct thread *child = get_child(pid); // todo
    // sema_down(&child->load_sema); //todo
    // if (child->load_done) //todo
    f->eax = pid;
    break;
  }
  case SYS_WAIT:
  {
    read_arg(esp, argv, 1);
    tid_t pid = argv[0];
    int status = process_wait(pid);
    f->eax = status;
    break;
  }
  case SYS_READ:
  {
    // check_user_vaddr(f->esp + 20);
    // check_user_vaddr(f->esp + 24);
    // check_user_vaddr(f->esp + 28);
    read((int)*(uint32_t *)(f->esp + 20), (void *)*(uint32_t *)(f->esp + 24), (unsigned)*((uint32_t *)(f->esp + 28)));
    break;
  }
  }
}

/* [ADDED_Lab2_system_call] */
void is_userArea(void *uaddr)
{
  // check that a user pointer `uaddr` points below PHYS_BASE
  uint32_t val = (unsigned int)uaddr;
  uint32_t min_address = 0x8048000;
  uint32_t max_address = PHYS_BASE;

  if (val < min_address || val >= max_address)
  {
    printf("\nnot userArea\n");
    sys_exit(-1);
  }
}
/* [ADDED_Lab2_system_call] */
void read_arg(void *esp, int *arg, int num_arg_item)
{
  if (num_arg_item <= 0)
    return;

  int p;
  void *ptr = esp + 4;
  for (p = 0; p < num_arg_item; p++)
  {
    is_userArea(ptr);
    arg[p] = *(int *)ptr;
    ptr += 4;
  }
}
/* [ADDED_Lab2_system_call] */
void sys_exit(int exit_status)
{
  struct thread *t = thread_current();
  t->exit_status = exit_status;
  printf("%s: exit(%d)\n", thread_name(), exit_status);
  thread_exit();
}

// todo -------------------아래 다
int write(int fd, const void *buffer, unsigned size)
{
  if (fd == 1)
  {
    putbuf(buffer, size);
    return size;
  }
  return -1;
}
// todo
// pid_t exec(const char *cmd_line)
// {
//   return process_execute(cmd_line);
// }
//
int read(int fd, void *buffer, unsigned size)
{
  int i;
  if (fd == 0)
  {
    for (i = 0; i < size; i++)
    {
      if (((char *)buffer)[i] == '\0')
      {
        break;
      }
    }
  }
  return i;
}