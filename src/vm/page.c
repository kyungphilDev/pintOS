#include "vm/page.h"

// Init the Hash Table
void vm_init(struct hash *vm)
{
  hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

// Destroy the Hash Table
void vm_destroy(struct hash *vm)
{
  hash_destroy(vm, vm_destroy_func);
}

// Return Hash Value
static unsigned vm_hash_func(const struct hash_elem *e, void *aux)
{
  struct vm_entry *vm = hash_entry(e, struct vm_entry, elem);

  return hash_int(vm->vaddr);
}

// If a->vaddr < b->vaddr, return true. Otherwise, return false
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
  return hash_entry(a, struct vm_entry, elem)->vaddr < hash_entry(b, struct vm_entry, elem)->vaddr;
}

// destroy the vm_entry
static void vm_destroy_func(struct hash_elem *e, void *aux)
{
  struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);

  // If vme is loaded, free the kpage & delete pte from page table
  if (vme->is_loaded)
  {
    palloc_free_page(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
    // free_page(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
    pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
  }

  // Free the vme
  free(vme);
}

// Find the vm_entry object that got vaddr.
struct vm_entry *find_vme(void *vaddr)
{
  struct vm_entry vm;
  struct hash_elem *h;
  struct thread *cur = thread_current();

  vm.vaddr = pg_round_down(vaddr);

  h = hash_find(&cur->vm, &vm.elem);

  if (h == NULL)
  {
    return h;
  }

  return hash_entry(h, struct vm_entry, elem);
}
bool insert_vme(struct hash *vm, struct vm_entry *vme)
{
  return (hash_insert(vm, &vme->elem) == NULL) ? true : false;
}
bool delete_vme(struct hash *vm, struct vm_entry *vme)
{
  return (hash_delete(vm, &vme->elem) != NULL) ? true : false;
}

struct page *alloc_page(enum palloc_flags flags)
{
  struct page *page;
  void *kaddr = palloc_get_page(flags);

  while (kaddr == NULL)
  {
    kaddr = try_to_free_pages(flags);
  }

  page = (struct page *)malloc(sizeof(struct page));
  page->kaddr = kaddr;
  page->thread = thread_current();

  add_page_to_lru_list(page);

  return page;
}

void do_free_page(struct page *page)
{
  page->vme->is_loaded = false;
  del_page_from_lru_list(page);
  pagedir_clear_page(page->thread->pagedir, page->vme->vaddr);
  palloc_free_page(page->kaddr);
  free(page);
}

void free_page(void *kaddr)
{
  struct page *page = find_page(kaddr);

  if (page != NULL)
  {
    do_free_page(page);
  }
}
