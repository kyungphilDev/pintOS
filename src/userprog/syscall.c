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
/* ---------------- [ADDED_LAB3] ---------------- */
#include "vm/page.h"
int mmap(int fd, void *addr);
void munmap(int map_id);
void do_munmap(struct mmap_file *mmap_f);
struct vm_entry *is_addr_right(void *addr, void *esp);
void is_buffer_ok(void *buffer, unsigned size, void *esp, bool to_write);
void is_string_ok(const void *str, void *esp);
/* ------------------------------------------------ */
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
    is_string_ok((void *)argv[1], esp);
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
    is_string_ok((void *)argv[0], esp);
    bool ret = filesys_create(file, size_file);
    f->eax = ret; // set return value
    break;
  }
  case SYS_REMOVE:
  {
    read_arg(esp, argv, 1); // read remove args
    char *fileName = (char *)argv[0];
    is_string_ok((void *)argv[0], esp);
    bool ret = filesys_remove(fileName);
    f->eax = ret;
    break;
  }
  case SYS_OPEN:
  {
    read_arg(esp, argv, 1); // read open args
    char *fileName = (char *)argv[0];
    is_string_ok((void *)argv[0], esp);
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
    is_string_ok((void *)argv[0], esp);
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
    is_buffer_ok((void *)argv[1], argv[2], esp, true);
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
  case SYS_MMAP:
    read_arg(esp, argv, 2); // read filesize args
    f->eax = mmap(argv[0], (void *)argv[1]);
    break;
  case SYS_MUNMAP:
    read_arg(esp, argv, 1); // read filesize args
    munmap(argv[0]);
    break;
  default:
    thread_exit();
    break;
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
  struct thread *cur;
  cur = thread_current();                           // Get Running Thread
  cur->exit_status = exit_status;                   // Save Exit Status
  printf("%s: exit(%d)\n", cur->name, exit_status); // Output Exit Message
  thread_exit();                                    // Exit Thread
}
void sys_close(int num_fd)
{
  struct file *fp = thread_current()->file_descriptor[num_fd];
  check_file_NULL(fp);
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
/* [ADDED_LAB3] */
struct vm_entry *is_addr_right(void *addr, void *esp)
{
  struct vm_entry *vme;
  uint32_t address = (uint32_t)addr;

  if (!(0x8048000 < address && address < 0xc0000000))
  {
    sys_exit(-1);
  }

  vme = search_vm_entry(addr);

  if (!vme)
  {
    if (expand_stack(esp, addr))
    {
      vme = search_vm_entry(addr);
    }
  }

  return vme;
}
/* [ADDED_LAB3] */
void is_string_ok(const void *str, void *esp)
{
  int i, pages;
  struct vm_entry *vme_start = is_addr_right(str, esp);
  struct vm_entry *vme_end = is_addr_right(str + strlen((char *)str), esp);
  struct vm_entry *vme;

  pages = ((int)(vme_start->vaddr - vme_end->vaddr) / PGSIZE) + 1;
  for (i = 0; i < pages; i++)
  {
    vme = is_addr_right(str + (PGSIZE * i), esp);

    if (vme == NULL)
    {
      sys_exit(-1);
    }
  }
}
/* [ADDED_LAB3] */
void is_buffer_ok(void *buffer, unsigned size, void *esp, bool to_write)
{
  int i, pages;
  struct vm_entry *vme_start = is_addr_right(buffer, esp);
  struct vm_entry *vme_end = is_addr_right(buffer + size, esp);
  struct vm_entry *vme;
  pages = ((int)(vme_start->vaddr - vme_end->vaddr) / PGSIZE) + 1;
  for (i = 0; i < pages; i++)
  {
    vme = is_addr_right(buffer + (PGSIZE * i), esp);

    if (vme == NULL || !vme->write_ok)
    {
      sys_exit(-1);
    }
  }
}
/* [ADDED_LAB3] */
int mmap(int fd, void *addr)
{
  struct thread *cur = thread_current();
  struct vm_entry *vme;
  size_t read_bytes = 0;
  size_t page_read_bytes = 0;
  size_t page_zero_bytes = 0;
  size_t ofs = 0;
  struct list_elem *elem;
  struct list_elem *tail = list_tail(&cur->mmap_list);
  struct file *f;
  struct mmap_file *mmap_f;
  struct inode *i;

  f = thread_current()->file_descriptor[fd];
  if (f == NULL || ((int)addr % PGSIZE) || !addr)
  {
    return -1;
  }
  mmap_f = (struct mmap_file *)malloc(sizeof(struct mmap_file));
  mmap_f->map_id = (list_empty(&cur->mmap_list) == true) ? 0 : list_entry(list_end(&cur->mmap_list), struct mmap_file, elem)->map_id + 1;
  mmap_f->file = file_reopen(f);
  list_init(&mmap_f->vme_list);

  read_bytes = file_length(mmap_f->file);
  while (read_bytes > 0)
  {
    page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    page_zero_bytes = PGSIZE - page_read_bytes;
    if (search_vm_entry(addr) != NULL)
    {
      munmap(mmap_f->map_id);
      return -1;
    }
    vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));
    vme->type = FILE_VM;
    vme->vaddr = addr;
    vme->write_ok = true;
    vme->is_loaded = false;
    vme->m_file = mmap_f->file;
    vme->read_bytes = page_read_bytes;
    vme->zero_bytes = page_zero_bytes;
    vme->offset = ofs;
    list_push_back(&mmap_f->vme_list, &vme->mmap_elem);
    insert_vm_entry(&cur->vm, vme);
    read_bytes -= page_read_bytes;
    ofs += page_read_bytes;
    addr += PGSIZE;
  }
  list_push_back(&cur->mmap_list, &mmap_f->elem);
  return mmap_f->map_id;
}
/* [ADDED_LAB3] */
void do_munmap(struct mmap_file *mmap_f)
{
  struct thread *cur = thread_current();
  struct list_elem *elem;
  struct list_elem *tail_elem = list_tail(&mmap_f->vme_list);
  struct list_elem *tmp_elem;
  struct vm_entry *vme;
  for (elem = list_begin(&mmap_f->vme_list); elem != tail_elem;)
  {
    tmp_elem = list_next(elem);
    vme = list_entry(elem, struct vm_entry, mmap_elem);
    if (vme->is_loaded)
    {
      if (pagedir_is_dirty(cur->pagedir, vme->vaddr))
      {
        lock_acquire(&lock_file);
        file_write_at(vme->m_file, vme->vaddr, vme->read_bytes, vme->offset);
        lock_release(&lock_file);
      }
      palloc_free_page(pagedir_get_page(cur->pagedir, vme->vaddr));
      pagedir_clear_page(cur->pagedir, vme->vaddr);
    }
    list_remove(&vme->mmap_elem);
    delete_vm_entry(&thread_current()->vm, vme);
    free(vme);
    elem = tmp_elem;
  }
  lock_acquire(&lock_file);
  file_close(mmap_f->file);
  lock_release(&lock_file);
}
/* [ADDED_LAB3] */
void munmap(int map_id)
{
  struct thread *cur = thread_current();
  struct mmap_file *mmap_f;
  struct list_elem *elem;
  struct list_elem *tail_elem = list_tail(&cur->mmap_list);
  struct list_elem *tmp_elem;
  for (elem = list_begin(&cur->mmap_list); elem != tail_elem;)
  {
    mmap_f = list_entry(elem, struct mmap_file, elem);
    if (map_id == -1)
    {
      tmp_elem = list_next(elem);
      list_remove(elem);
      do_munmap(mmap_f);
      free(mmap_f);
      elem = tmp_elem;
    }
    else if (mmap_f->map_id == map_id)
    {
      break;
    }
    else
    {
      elem = list_next(elem);
    }
  }
  if (elem != tail_elem)
  {
    list_remove(elem);
    do_munmap(mmap_f);
    free(mmap_f);
  }
}