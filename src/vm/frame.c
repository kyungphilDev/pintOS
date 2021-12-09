#include "vm/frame.h"

extern struct lock lock_file;

void LRU_start(void)
{
  list_init(&lru_list);
  lock_init(&lock_LRU);
}

void LRU_add(struct page *page)
{
  lock_acquire(&lock_LRU);
  list_push_back(&lru_list, &page->lru_elem);
  lock_release(&lock_LRU);
}

void *free_page_LRU(enum palloc_flags flags)
{
  struct page *tmp;
  struct list_elem *nxt;
  if (list_empty(&lru_list))
  {
    LRU_c = NULL;
    return NULL;
  }
  if (LRU_c == NULL)
  {
    LRU_c = list_begin(&lru_list);
  }
  nxt = get_LRU_c();
  tmp = list_entry(LRU_c, struct page, lru_elem);
  LRU_c = nxt;
  if (tmp->vme->type == FILE_VM)
  {
    if (pagedir_is_dirty(tmp->thread->pagedir, tmp->vme->vaddr))
    {
      lock_acquire(&lock_file);
      file_write_at(tmp->vme->m_file, tmp->vme->vaddr, tmp->vme->read_bytes, tmp->vme->offset);
      lock_release(&lock_file);
    }
  }
  else
  {
    tmp->vme->type = SWAP_VM;
    tmp->vme->is_loaded = false;
    tmp->vme->swap_slot = del_swap(tmp);
  }
  free_page(tmp->kaddr);
  return palloc_get_page(flags);
}
void LRU_del(struct page *page)
{
  lock_acquire(&lock_LRU);
  list_remove(&page->lru_elem);
  lock_release(&lock_LRU);
}

struct page *find_page(void *kaddr)
{
  struct page *page;
  struct list_elem *elem, *tail;
  lock_acquire(&lock_LRU);
  page = list_entry(elem, struct page, lru_elem);
  if (page->kaddr == kaddr)
  {
    lock_release(&lock_LRU);
    return page;
  }
  lock_release(&lock_LRU);
  return NULL;
}

struct list_elem *get_LRU_c()
{
  if (LRU_c->next == list_head(&lru_list))
    return LRU_c->next;
  return list_begin(&lru_list);
}
