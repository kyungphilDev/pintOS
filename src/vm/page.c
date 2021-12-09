#include "vm/page.h"

static unsigned vm_hash(const struct hash_elem *hash_e, void *aux);
static bool comp_less_vm(const struct hash_elem *a, const struct hash_elem *b, void *aux);
static void delete_vm_hash(struct hash_elem *hash_e, void *aux);

void start_vm(struct hash *vm)
{
  hash_init(vm, vm_hash, comp_less_vm, NULL);
}
static unsigned vm_hash(const struct hash_elem *hash_e, void *aux)
{
  struct vm_entry *vm = hash_entry(hash_e, struct vm_entry, elem);

  return hash_int(vm->vaddr);
}

void delete_vm(struct hash *vm)
{
  hash_destroy(vm, delete_vm_hash);
}

static bool comp_less_vm(const struct hash_elem *hash_A, const struct hash_elem *hash_B, void *aux)
{
  const struct vm_entry *hash_vm_A = hash_entry(hash_A, struct vm_entry, elem);
  const struct vm_entry *hash_vm_B = hash_entry(hash_B, struct vm_entry, elem);

  return hash_vm_A->vaddr < hash_vm_B->vaddr;
}

static void delete_vm_hash(struct hash_elem *hash_e, void *aux)
{
  struct vm_entry *vme = hash_entry(hash_e, struct vm_entry, elem);
  if (vme->is_loaded)
  {
    palloc_free_page(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
    pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
  }
  free(vme);
}

struct vm_entry *search_vm_entry(void *vaddr)
{
  struct vm_entry vm;
  struct hash_elem *hash_e;
  struct thread *cur = thread_current();
  vm.vaddr = pg_round_down(vaddr);
  hash_e = hash_find(&cur->vm, &vm.elem);
  if (hash_e == NULL)
  {
    return hash_e;
  }
  return hash_entry(hash_e, struct vm_entry, elem);
}
bool insert_vm_entry(struct hash *vm, struct vm_entry *vme)
{
  if (hash_insert(vm, &vme->elem) == NULL)
    return true;
  return false;
}
bool delete_vm_entry(struct hash *vm, struct vm_entry *vme)
{
  if (hash_delete(vm, &vme->elem) != NULL)
    return true;
  return false;
}

struct page *page_alloc(enum palloc_flags palloc_f)
{
  struct page *page;
  void *addr = palloc_get_page(palloc_f);
  while (addr == NULL)
  {
    addr = free_page_LRU(palloc_f);
  }
  page = (struct page *)malloc(sizeof(struct page));
  page->thread = thread_current();
  page->kaddr = addr;
  return page;
}

void free_page(void *kaddr)
{
  struct page *page = find_page(kaddr);

  if (page != NULL)
  {
    page->vme->is_loaded = false;
    palloc_free_page(page->kaddr);
    free(page);
  }
}
