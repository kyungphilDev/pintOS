#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

// added_lab3
#include "vm/page.h"
bool handle_mm_fault(struct vm_entry *vme);
bool load_file(void *kaddr, struct vm_entry *vme);

static thread_func start_process NO_RETURN;
static bool load(const char *cmdline, void (**eip)(void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute(const char *file_name)
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  /* [EDITED_Lab2_argument_passing] */
  int len_file_name = strlen(file_name) + 1; // strlcpy -> size -1
  char tmp_file_name[len_file_name];
  strlcpy(tmp_file_name, file_name, len_file_name); // copy file_name for tokenizing
  char *unused_ptr = NULL;
  char *token_file_name = strtok_r(tmp_file_name, " ", &unused_ptr);

  /* Create a new thread to execute FILE_NAME. */
  if (filesys_open(token_file_name) == NULL) // for null teststing
    return -1;
  // printf("\n kyungphil_check: %s\n\n", token_file_name);
  tid = thread_create(token_file_name, PRI_DEFAULT, start_process, fn_copy);
  sema_down(&thread_current()->load_lock); // [ADDED_project2_parent_child_hierarchy]
  if (tid == TID_ERROR)
    palloc_free_page(fn_copy);
  // [ADDED_project2_parent_child_hierarchy]
  struct list_elem *e;
  for (e = list_begin(&thread_current()->child_list); e != list_end(&thread_current()->child_list); e = list_next(e))
  {
    struct thread *t = list_entry(e, struct thread, child_elem);
    if (t->load_done == false)
      return process_wait(tid);
  }
  return tid;
}
/* [ADDED_Lab2_argument_passing] */
void save_stack(char **argv_item_list, int argc, void **esp)
{
  int len_tot = 0;
  unsigned int argv_item_address[argc];
  if (argv_item_list == NULL)
  {
    return;
  }
  /* ------ push argv items ------ */
  int p, q;
  for (p = argc - 1; p > -1; p--)
  {
    int len_token = strlen(argv_item_list[p]);
    for (q = len_token; q > -1; q--)
    {
      *esp -= 1;
      **(char **)esp = argv_item_list[p][q];
      len_tot++;
    }
    argv_item_address[p] = *(unsigned int *)esp;
  }
  // push word-align area for 4 multiple address
  int len_word_align = 4 - (len_tot % 4);
  for (p = 0; p < len_word_align; p++)
  {
    *esp -= 1;
    **(uint8_t **)esp = 0;
  }
  /* ------ push argv item's address ------ */
  // end of argv
  *esp -= 4;
  **(char ***)esp = 0;
  for (p = argc - 1; p > -1; p--)
  {
    *esp -= 4;
    **(char ***)esp = (char *)argv_item_address[p];
  }
  /* ------ push argv address ------ */
  unsigned int argv_address;
  argv_address = *(unsigned int *)esp;
  *esp -= 4;
  **(char ***)esp = (char *)argv_address;
  /* ------ push argc address ------ */
  *esp -= 4;
  **(int **)esp = argc;
  /* push empty return Address */
  *esp -= 4;
  **(int **)esp = 0;
}

/* [ADDED_Lab2_argument_passing] */
int tokenize(char **token_list, char *file_name)
{
  char *token;
  char *left_file_name;
  int cnt = 0;
  token = strtok_r(file_name, " ", &left_file_name);
  while (token != NULL)
  {
    token_list[cnt] = token;
    cnt++;
    token = strtok_r(NULL, " ", &left_file_name);
  }
  return cnt;
}
/* A thread function that loads a user process and starts it
   running. */
static void
start_process(void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* [ADDED_Lab2_argument_passing] */
  char **argv;
  char *token;
  char *saveptr;
  int argc = 0;
  int i;
  for (token = strtok_r(file_name, " ", &saveptr);
       token != NULL;
       token = strtok_r(NULL, " ", &saveptr))
  {
    if (argc == 0)
    {
      argv = palloc_get_page(0);
    }
    argv[argc] = palloc_get_page(0);
    strlcpy(argv[argc++], token, strlen(token) + 1);
  }
  // added_lab3
  vm_init(&thread_current()->vm);
  list_init(&thread_current()->mmap_list);
  // char *token_list[LOADER_ARGS_LEN / 2 + 1];
  // int cnt_token = tokenize(token_list, file_name);
  // char *file_name_token = token_list[0];
  /* ----------------------------- */
  /* Initialize interrupt frame and load executable. */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load(file_name, &if_.eip, &if_.esp); // [EDITED_Lab2_argument_passing]

  /* [EDITED_Lab2_argument_passing] */
  thread_current()->load_done = success; // check whether load completed or not
  sema_up(&thread_current()->parent_thread->load_lock);

  /* If load failed, quit. */
  palloc_free_page(file_name);
  if (!success)
  {
    for (i = 0; i < argc; i++)
    {
      palloc_free_page(argv[i]);
    }
    palloc_free_page(argv);
    thread_exit();
  }
  if (success)
  {
    /* [EDITED_Lab2_argument_passing] */
    save_stack(argv, argc, &if_.esp);
    // hex_dump(if_.esp, if_.esp, PHYS_BASE - if_.esp, true);
  }
  /* ----------------------------- */

  /* free */
  for (i = 0; i < argc; i++)
  {
    palloc_free_page(argv[i]);
  }
  palloc_free_page(argv);
  // if (!success)
  //   sys_exit(-1);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit"
               :
               : "g"(&if_)
               : "memory");
  NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(tid_t child_tid)
{
  struct thread *child = get_child(child_tid);
  if (child == NULL)
    return -1;
  sema_down(&child->exit_sema);               // wait for child process done
  int child_exit_status = child->exit_status; // initiate child's exist status
  remove_child(child);
  sema_up(&child->load_sema);
  return child_exit_status;
}

/* Free the current process's resources. */
void process_exit(void)
{
  struct thread *cur = thread_current();
  uint32_t *pd;

  // added_lab3
  if (cur->parent_thread != NULL)
  {
    munmap(-1);
    vm_destroy(&cur->vm);
  }
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
  {
    /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }
  /* [ADDED_Lab2_parent_child] */
  sema_up(&cur->exit_sema);
  sema_down(&cur->load_sema);
  /* -------------------------- */
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void)
{
  struct thread *t = thread_current();

  /* Activate thread's page tables. */
  pagedir_activate(t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void **esp);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char *file_name, void (**eip)(void), void **esp)
{
  struct thread *t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create();
  if (t->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL)
  {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024)
  {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
  {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type)
    {
    case PT_NULL:
    case PT_NOTE:
    case PT_PHDR:
    case PT_STACK:
    default:
      /* Ignore this segment. */
      break;
    case PT_DYNAMIC:
    case PT_INTERP:
    case PT_SHLIB:
      goto done;
    case PT_LOAD:
      if (validate_segment(&phdr, file))
      {
        bool writable = (phdr.p_flags & PF_W) != 0;
        uint32_t file_page = phdr.p_offset & ~PGMASK;
        uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
        uint32_t page_offset = phdr.p_vaddr & PGMASK;
        uint32_t read_bytes, zero_bytes;
        if (phdr.p_filesz > 0)
        {
          /* Normal segment.
                     Read initial part from disk and zero the rest. */
          read_bytes = page_offset + phdr.p_filesz;
          zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
        }
        else
        {
          /* Entirely zero.
                     Don't read anything from disk. */
          read_bytes = 0;
          zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
        }
        if (!load_segment(file, file_page, (void *)mem_page,
                          read_bytes, zero_bytes, writable))
          goto done;
      }
      else
        goto done;
      break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
  {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;
    // added_lab3
    // Create the vm_entry Object
    struct vm_entry *vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));

    // Init the member of vm_entry
    vme->type = VM_BIN;                // Binary File
    vme->vaddr = upage;                // get virtual address from Program Header of ELF
    vme->writable = writable;          // whether write is possible or impossible
    vme->is_loaded = false;            // whether page is loaded or isn't loaded to physical memory
    vme->file = file;                  // Mapped File
    vme->offset = ofs;                 // Offset to read the file
    vme->read_bytes = page_read_bytes; // Count of bytes to read
    vme->zero_bytes = page_zero_bytes; // Count of bytes to pad the 0

    insert_vme(&thread_current()->vm, vme); // Insert to hash table

    /* Get a page of memory. */
    uint8_t *kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
    {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable))
    {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
    ofs += PGSIZE; // added_lab3
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack(void **esp)
// {
//   struct vm_entry *vme;
//   struct page *page;
//   uint8_t *kpage;
//   bool success = false;

//   //kpage = palloc_get_page (PAL_USER | PAL_ZERO);
//   page = alloc_page(PAL_USER | PAL_ZERO);

//   if (/*kpage != NULL*/ page->kaddr != NULL)
//   {
//     success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, page->kaddr /*kpage*/, true);
//     if (success)
//       *esp = PHYS_BASE;
//     else
//     {
//       //palloc_free_page (kpage);
//       free_page(page->kaddr);
//     }
//   }

//   // Create the vm_entry Object
//   vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));

//   // Init the member of vm_entry
//   vme->type = VM_ANON;                          // Stack has not file, so i'm init like that
//   vme->vaddr = ((uint8_t *)PHYS_BASE) - PGSIZE; // virtual address
//   vme->writable = success;
//   vme->is_loaded = success;
//   vme->file = NULL;
//   vme->offset = 0;
//   vme->read_bytes = 0;
//   vme->zero_bytes = 0;

//   insert_vme(&thread_current()->vm, vme);

//   //printf("vme->vaddr (stack) : %p\n", vme->vaddr);

//   page->vme = vme;

//   return success;
// }

{
  struct vm_entry *vme;
  struct page *page;
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL)
  {
    success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }

  // Create the vm_entry Object
  vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));

  // Init the member of vm_entry
  vme->type = VM_ANON;                          // Stack has not file, so i'm init like that
  vme->vaddr = ((uint8_t *)PHYS_BASE) - PGSIZE; // virtual address
  vme->writable = success;
  vme->is_loaded = success;
  vme->file = NULL;
  vme->offset = 0;
  vme->read_bytes = 0;
  vme->zero_bytes = 0;

  insert_vme(&thread_current()->vm, vme);

  //printf("vme->vaddr (stack) : %p\n", vme->vaddr);

  // page->vme = vme;

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pagedir, upage) == NULL && pagedir_set_page(t->pagedir, upage, kpage, writable));
}
/* [ADDED_Lab2_parent_child] */
struct thread *get_child(int pid)
{
  struct list_elem *p_elem = list_begin(&thread_current()->child_list);

  while (p_elem != list_end(&thread_current()->child_list))
  {
    struct thread *cur = list_entry(p_elem, struct thread, child_elem);
    if (cur->tid == pid)
      return cur;
    p_elem = list_next(p_elem);
  }
  return NULL;
}
void *remove_child(struct thread *p_cur)
{
  if (p_cur == NULL)
    return;
  list_remove(&p_cur->child_elem);
}

// added_lab3
bool handle_mm_fault(struct vm_entry *vme)
{
  void *kaddr;
  struct page *page;
  bool flag_load;

  kaddr = palloc_get_page(PAL_USER);
  // page = alloc_page(PAL_USER);
  // page->vme = vme;
  //printf("-------------------------------------------------- %d\n", vme->type);
  switch (vme->type)
  {
  case VM_BIN:
  case VM_FILE:
    // case VM_ANON:
    flag_load = load_file(kaddr, vme);
    // flag_load = load_file(page->kaddr, page->vme);
    break;
  // case VM_ANON:
  // flag_load = swap_in(vme->swap_slot, page->kaddr);
  //   break;
  default:
    return false;
  }

  if (!flag_load)
  {
    // free_page(page->kaddr);
    palloc_free_page(kaddr);
    return false;
  }
  // vme->is_loaded = install_page(vme->vaddr, /*kaddr*/ page->kaddr, vme->writable);
  vme->is_loaded = install_page(vme->vaddr, /*kaddr*/ kaddr, vme->writable);

  if (!vme->is_loaded)
  {
    palloc_free_page(kaddr);
    // free_page(page->kaddr);
  }

  return vme->is_loaded;
}
bool load_file(void *kaddr, struct vm_entry *vme)
{
  int reads;

  if (vme->read_bytes > 0)
  {
    reads = file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset);
    if (reads != (int)vme->read_bytes)
    {
      palloc_free_page(kaddr);
      // free_page(kaddr);
      return false;
    }
    memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);
  }
  else
  {
    memset(kaddr, 0, PGSIZE);
  }
  return true;
}

#define STACK_LIMIT PHYS_BASE - (8 * 1024 * 1024)

bool expand_stack(void *sp, void *addr)
{
  struct vm_entry *vme;
  struct page *page;
  void *vaddr;
  bool success = false;

  if (addr < sp - 32 || addr < STACK_LIMIT || !addr || !sp)
  {
    //printf("sp : %p\taddr : %p\n", sp, addr);
    return false;
  }

  //printf("%p ==========\n", addr);

  vaddr = pg_round_down(addr);

  // uint8_t *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  page = alloc_page(PAL_USER | PAL_ZERO);

  if (page != NULL)
  {
    success = install_page(vaddr, page->kaddr, true);
    // success = install_page(vaddr, kpage, true);
    if (!success)
    {
      // palloc_free_page(kpage);
      free_page(page->kaddr);
      return false;
    }
  }

  vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));
  vme->type = VM_ANON;
  vme->vaddr = pg_round_down(addr);
  vme->writable = true;
  vme->is_loaded = success;
  vme->file = NULL;
  vme->offset = 0;
  vme->read_bytes = 0;
  vme->zero_bytes = 0;

  insert_vme(&thread_current()->vm, vme);

  page->vme = vme;

  return success;
}
