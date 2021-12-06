#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
/* [ADDED_Lab2_system_call] */
#include <devices/shutdown.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "threads/synch.h"
#define PHYS_BASE 0xc0000000
/* [ADDED_Lab2_Denying_write] */
#define FD_STDIN 0
#define FD_STDOUT 1
#include "filesys/off_t.h"
struct file
{
  struct inode *inode; /* File's inode. */
  off_t pos;           /* Current position. */
  bool deny_write;     /* Has file_deny_write() been called? */
};
/* -------------------------- */
static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  lock_init(&lock_file); // [ADDED_Lab2_read_write_syncronization]
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f)
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
    sys_exit(exit_status);
    break;
  }
  case SYS_WRITE:
  {
    read_arg(esp, argv, 3);
    int ret = -1;
    int num_fd = argv[0];
    void *buf = (void *)argv[1];
    unsigned file_size = (unsigned)argv[2];

    is_userArea(buf);
    lock_acquire(&lock_file); // [ADDED_for the file syncronization]
    if (num_fd == FD_STDOUT)  // Monitor File Object
    {
      putbuf(buf, file_size);
      ret = file_size;
    }
    else if (num_fd > 2) // I/O File Object
    {
      struct file *file_descriptor_ptr = thread_current()->file_descriptor[num_fd];
      if (file_descriptor_ptr == NULL)
      {
        lock_release(&lock_file);
        sys_exit(-1);
      }
      ret = file_write(file_descriptor_ptr, buf, file_size);
    }
    lock_release(&lock_file);
    f->eax = ret; // set return value
    break;
  }
  case SYS_CREATE:
  {
    read_arg(esp, argv, 2); // read create args
    char *file = (char *)argv[0];
    unsigned size_file = argv[1];
    if (file == NULL)
    {
      sys_exit(-1);
    }
    bool ret = filesys_create(file, size_file);
    f->eax = ret; // set return value
    break;
  }
  case SYS_REMOVE:
  {
    read_arg(esp, argv, 1); // read remove args
    // is_userArea((void *)argv[0]);
    char *fileName = (char *)argv[0];
    check_file_name_NULL(fileName);
    bool ret = filesys_remove(fileName);
    f->eax = ret;
    break;
  }
  case SYS_OPEN:
  {
    read_arg(esp, argv, 1); // read open args
    char *fileName = (char *)argv[0];
    check_file_name_NULL(fileName);
    lock_acquire(&lock_file);
    struct file *file_open = filesys_open(fileName);
    if (file_open == NULL) // open failed
    {
      f->eax = -1;
      lock_release(&lock_file);
      break;
    }
    int i;
    for (i = 3; i < 128; i++) // I/O File Object
    {
      if (thread_current()->file_descriptor[i] == NULL)
      {
        if (strcmp(thread_current()->name, fileName) == 0)
        {
          // printf("check denying\n");
          file_deny_write(file_open);
        }
        thread_current()->file_descriptor[i] = file_open;
        f->eax = i;
        break;
      }
    }
    lock_release(&lock_file);
    break;
  }
  case SYS_FILESIZE:
  {
    read_arg(esp, argv, 1); // read filesize args
    int num = (int)argv[0];
    struct file *file_fd = thread_current()->file_descriptor[num];
    check_file_NULL(file_fd);
    f->eax = file_length(file_fd);
    break;
  }
  case SYS_EXEC:
  {
    read_arg(esp, argv, 1);
    char *exec_file = (char *)argv[0];
    tid_t pid = process_execute(exec_file);
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
    read_arg(esp, argv, 3); // read args for read-op
    int num_fd = argv[0];
    void *buf = (void *)argv[1];
    unsigned size_file = argv[2];
    is_userArea(buf);
    lock_acquire(&lock_file);
    if (num_fd == FD_STDIN) //STDIN
    {
      int p;
      for (p = 0; p < size_file; p++)
      {
        if (((char *)buf)[p] == '\0')
          break;
      }
      f->eax = p;
      lock_release(&lock_file);
      break;
    }
    int ret;
    if (num_fd > 2)
    {
      struct file *file_fd = thread_current()->file_descriptor[num_fd];
      check_file_NULL(file_fd);
      ret = file_read(file_fd, buf, size_file);
    }
    f->eax = ret;
    lock_release(&lock_file);
    break;
  }
  case SYS_SEEK:
  {
    read_arg(esp, argv, 2); // read file args
    int num_fd = (int)argv[0];
    unsigned pos = argv[1];
    struct file *file_fd = thread_current()->file_descriptor[num_fd];
    check_file_NULL(file_fd);
    file_seek(file_fd, pos);
    break;
  }
  case SYS_TELL:
  {
    read_arg(esp, argv, 1); // read file args
    int fd_num = (int)argv[0];
    struct file *file_fd = thread_current()->file_descriptor[fd_num];
    check_file_NULL(file_fd);
    f->eax = (unsigned)file_tell(file_fd);
    break;
  }
  case SYS_CLOSE:
  {
    read_arg(esp, argv, 1); // read filesize args
    int num_fd = (int)argv[0];
    sys_close(num_fd);
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
    // printf("\nnot userArea\n");
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
  int p;
  for (p = 3; p < 128; p++)
  {
    if (thread_current()->file_descriptor[p] != NULL)
    {
      // printf("sys_exit\n");
      sys_close(p);
    }
  }
  thread_exit();
}
void sys_close(int num_fd)
{
  struct file *file_fd = thread_current()->file_descriptor[num_fd];
  check_file_NULL(file_fd);
  struct file *fp = thread_current()->file_descriptor[num_fd];
  thread_current()->file_descriptor[num_fd] = NULL;
  return file_close(fp);
}

/* [ADDED_Lab2_system_call] */
void check_file_name_NULL(char *file)
{
  if (file == NULL)
    sys_exit(-1);
}
void check_file_NULL(struct file *file_fd)
{
  if (file_fd == NULL)
    sys_exit(-1);
}
