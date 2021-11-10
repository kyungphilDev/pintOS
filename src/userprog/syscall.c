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

#define PHYS_BASE 0xc0000000;
//todo
#include "filesys/off_t.h"
struct file
{
  struct inode *inode; /* File's inode. */
  off_t pos;           /* Current position. */
  bool deny_write;     /* Has file_deny_write() been called? */
};

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  lock_init(&file_lock); // check
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
    read_arg(esp, argv, 3);
    // is_userArea((void *)argv[1]);
    f->eax = sys_write(argv[0], (void *)argv[1], (unsigned)argv[2]);
    break;
  }
  case SYS_CREATE: //check
  {
    read_arg(esp, argv, 2); // read create args
    // is_userArea((void *)argv[0]);
    // set return value of function
    char *file = (char *)argv[0];
    unsigned size_file = argv[1];
    if (file == NULL)
    {
      // printf("\nsys create\n");
      sys_exit(-1);
    }
    bool ret = filesys_create(file, size_file);
    f->eax = ret;
    break;
  }
  case SYS_REMOVE: //check
  {
    read_arg(esp, argv, 1); // read remove args
    // is_userArea((void *)argv[0]);
    char *file = (char *)argv[0];
    if (file == NULL)
    {
      printf("\nsys remove\n");
      sys_exit(-1);
    }
    bool ret = filesys_remove(file);
    f->eax = ret;
    break;
  }
  case SYS_OPEN: //check
  {
    read_arg(esp, argv, 1); // read open args
    // is_userArea((void *)argv[0]);
    char *file = (char *)argv[0];
    // f->eax = open(file);
    int ret = -1;
    if (file == NULL)
    {
      // printf("sys_open\n");
      sys_exit(-1);
    }
    lock_acquire(&file_lock);
    struct file *file_ptr = filesys_open(file);
    if (file_ptr)
    {
      // ret = add_to_fd(f, filename);
      for (int p = 3; p < 128; p++)
      {
        if (thread_current()->file_descriptor[p] == NULL)
        {
          thread_current()->file_descriptor[p] = file_ptr;
          ret = p;
          break;
        }
      }
    }
    lock_release(&file_lock);
    f->eax = ret;
    break;
  }
  case SYS_FILESIZE: //check
  {
    read_arg(esp, argv, 1); // read filesize args
    // is_userArea((void *)argv[0]);
    int num = (int)argv[0];
    if (thread_current()->file_descriptor[num] == NULL)
    {
      // printf("\nsys filesize\n");
      sys_exit(-1);
    }
    f->eax = file_length(thread_current()->file_descriptor[num]);

    // int fd, ret;
    // fd = fd_lookup(filename);
    // struct file *f_read = get_file(fd);
    // if (f_read != NULL)
    // {
    //   ret = file_length(f_read);
    // }
    // f->eax = ret;
    break;
  }
  case SYS_EXEC:
  {
    // printf("\n kyungphil_syscall\n");
    read_arg(esp, argv, 1);
    // is_userArea((void *)argv[0]);
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
  case SYS_READ: //check
  {
    read_arg(esp, argv, 3); // read args for read-op
    // is_userArea((void *)argv[0]);
    int fd = argv[0];
    void *buffer = (void *)argv[1];
    unsigned size_file = argv[2];
    int ret = read(fd, buffer, size_file);
    f->eax = ret;
    break;
  }
  case SYS_SEEK: //check
  {
    read_arg(esp, argv, 2); // read file args
    // is_userArea((void *)argv[0]);
    int num = (int)argv[0];
    unsigned pos = argv[1];
    if (thread_current()->file_descriptor[num] == NULL)
    {
      // printf("\nsys seek\n");
      sys_exit(-1);
    }
    file_seek(thread_current()->file_descriptor[num], pos);
    // int fd;
    // fd = fd_lookup(filename);
    // struct file *f_read = get_file(fd);
    // if (f_read != NULL)
    // {
    //   file_seek(f_read, pos);
    // }
    break;
  }
  case SYS_TELL: //check
  {
    read_arg(esp, argv, 1); // read file args
    // is_userArea((void *)argv[0]);
    int num = (int)argv[0];
    if (thread_current()->file_descriptor[num] == NULL)
    {
      // printf("\nsys tesll\n");
      sys_exit(-1);
    }
    f->eax = (unsigned)file_tell(thread_current()->file_descriptor[num]);
    // char *filename = (char *)argv[0];
    // int fd, ret;
    // fd = fd_lookup(filename);
    // struct file *f_read = get_file(fd);
    // if (f_read != NULL)
    // {
    //   ret = file_tell(f_read);
    // }
    // f->eax = ret;
    break;
  }
  case SYS_CLOSE: //check
  {
    read_arg(esp, argv, 1); // read filesize args
    // is_userArea((void *)argv[0]);
    int num = (int)argv[0];
    close(num);
    // if (thread_current()->file_descriptor[num] == NULL)
    // {
    //   sys_exit(-1);
    // }
    // file_close(thread_current()->file_descriptor[num]); //check
    // int fd;
    // fd = fd_lookup(filename);
    // if (fd >= 2)
    // {
    //   close_file(fd);
    // }
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
      close(p);
      // file_close(thread_current()->file_descriptor[p]); //check
    }
  }
  thread_exit();
}

// todo -------------------아래 다
int sys_write(int fd, const void *buffer, unsigned fd_size)
{
  if (fd == 1)
  {
    putbuf(buffer, fd_size);
    return fd_size;
  }
  else if (fd > 2)
  {
    struct file *file_descriptor_ptr = thread_current()->file_descriptor[fd];
    if (file_descriptor_ptr == NULL)
    {
      sys_exit(-1);
    }
    if (file_descriptor_ptr->deny_write)
    {
      file_deny_write(file_descriptor_ptr);
    }
    return file_write(file_descriptor_ptr, buffer, fd_size);
  }
  return -1;
}

int read(int fd, void *buffer, unsigned size)
{
  int i;
  int val;
  is_userArea(buffer);
  lock_acquire(&file_lock);
  is_userArea(buffer);
  if (fd == 0)
  {
    for (i = 0; i < size; i++)
    {
      if (((char *)buffer)[i] == '\0')
      {
        break;
      }
    }
    val = i;
  }
  else if (fd > 2)
  {
    if (thread_current()->file_descriptor[fd] == NULL)
    {
      // printf("\nsys read\n");
      sys_exit(-1);
    }
    val = file_read(thread_current()->file_descriptor[fd], buffer, size);
  }
  lock_release(&file_lock);
  return val;
  // lock_acquire(&file_lock);
  // if (fd == 0) //STDIN
  // {
  //   int i = size;
  //   char *buf = (char *)buffer;
  //   while (i--)
  //   {
  //     buf[i] = input_getc();
  //   }
  //   lock_release(&file_lock);
  //   return size;
  // }
  // else
  // {
  //   struct file *f = get_file(fd);
  //   if (f == NULL)
  //   {
  //     lock_release(&file_lock);
  //     return -1;
  //   }
  //   int i;
  //   i = file_read(f, buffer, size);
  //   lock_release(&file_lock);

  //   return i;
  // }
}

int write(int fd, void *buffer, unsigned size)
{
  int val = -1;
  is_userArea(buffer);
  lock_acquire(&file_lock);

  if (fd == 1)
  {
    putbuf(buffer, size);
    val = size;
  }
  else if (fd > 2)
  {
    struct file *file_descriptor_ptr = thread_current()->file_descriptor[fd];

    if (file_descriptor_ptr == NULL)
    {
      lock_release(&file_lock);
      sys_exit(-1);
    }
    if (file_descriptor_ptr->deny_write)
    {
      file_deny_write(file_descriptor_ptr);
    }
    val = file_write(file_descriptor_ptr, buffer, size);
  }
  lock_release(&file_lock);
  return val;
  // lock_acquire(&file_lock);
  // if (fd == 1) //STDOUT
  // {
  //   putbuf(buffer, size);
  //   lock_release(&file_lock);
  //   return size;
  // }
  // else
  // {
  //   struct file *f = get_file(fd);
  //   if (f == NULL)
  //   {
  //     lock_release(&file_lock);
  //     return -1;
  //   }
  //   int i;
  //   i = file_write(f, buffer, size);
  //   lock_release(&file_lock);

  //   return i;
  // }
}

// int fd_lookup(char *filename) //filename to fd
// {
//   struct thread *t = thread_current();
//   int i = 2;
//   for (i = 2; i < 128; i++)
//   {
//     if (strcmp(filename, t->fd_name[i]) == 0)
//     {
//       return i;
//     }
//   }
//   return -1;
// }

// todo delete
//
int open(const char *file)
{
  int i;
  int val = 1;
  if (file == NULL)
  {
    sys_exit(-1);
  }
  lock_acquire(&file_lock);
  struct file *fp = filesys_open(file);
  if (fp == NULL)
  {
    val = -1;
  }
  else
  {
    for (i = 3; i < 128; i++)
    {
      if (thread_current()->file_descriptor[i] == NULL)
      {
        if (strcmp(thread_current()->name, file) == 0)
        {
          printf("check denying\n");
          file_deny_write(fp);
        }
        thread_current()->file_descriptor[i] = fp;
        val = i;
        break;
      }
    }
  }
  lock_release(&file_lock);
  return val;
}
void close(int fd)
{
  if (thread_current()->file_descriptor[fd] == NULL)
  {
    // printf("\nsysclose\n");
    sys_exit(-1);
  }
  struct file *fp = thread_current()->file_descriptor[fd];
  thread_current()->file_descriptor[fd] = NULL;
  return file_close(fp);
}