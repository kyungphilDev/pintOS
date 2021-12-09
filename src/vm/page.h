#ifndef PAGE_H
#define PAGE_H

#include <stdint.h>
#include <hash.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/pte.h"

#define BINARY_VM 0
#define FILE_VM 1
#define SWAP_VM 2

struct vm_entry
{
  uint8_t type;
  void *vaddr;
  bool write_ok;

  bool is_loaded;
  bool pinned;
  struct file *m_file;
  struct list_elem mmap_elem;
  size_t offset;
  size_t read_bytes;
  size_t zero_bytes;
  size_t swap_slot;
  struct hash_elem elem;
};

struct mmap_file
{
  int map_id;
  struct file *file;
  struct list_elem elem;
  struct list vme_list;
};

struct page
{
  struct vm_entry *vme;
  struct thread *thread;
  struct list_elem lru_elem;
  void *kaddr;
};

void start_vm(struct hash *vm);
void delete_vm(struct hash *vm);
struct vm_entry *search_vm_entry(void *vaddr);
bool insert_vm_entry(struct hash *vm, struct vm_entry *vme);
bool delete_vm_entry(struct hash *vm, struct vm_entry *vme);
struct page *page_alloc(enum palloc_flags palloc_f);
void free_page(void *kaddr);

#endif
