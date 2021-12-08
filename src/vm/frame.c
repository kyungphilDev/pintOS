#include "vm/frame.h"

extern struct lock lock_file;

void lru_list_init(void)
{
  list_init(&lru_list);
  lock_init(&lru_list_lock);
}

void add_page_to_lru_list(struct page *page)
{
  lock_acquire(&lru_list_lock);
  list_push_back(&lru_list, &page->lru);
  lock_release(&lru_list_lock);
}

void del_page_from_lru_list(struct page *page)
{
  lock_acquire(&lru_list_lock);
  list_remove(&page->lru);
  lock_release(&lru_list_lock);
}

void *try_to_free_pages(enum palloc_flags flags)
{
  struct page *victim;
  struct list_elem *next;

  if (list_empty(&lru_list))
  {
    lru_clock = NULL;
    return NULL;
  }

  if (lru_clock == NULL)
  {
    lru_clock = list_begin(&lru_list);
  }

  /*for (	elem = get_lru_clock();
		; set_next_lru_clock(), elem = get_lru_clock())
	{
		victim = list_entry (elem, struct page, lru);
		if (!pagedir_is_accessed(victim->thread->pagedir, victim->vme->vaddr))
		{
			set_next_lru_clock();
			break;
		}

		pagedir_set_accessed(victim->thread->pagedir, victim->vme->vaddr, 0);
	}*/
  for (;;)
  {
    next = get_next_lru_clock();

    victim = list_entry(lru_clock, struct page, lru);

    lru_clock = next;

    if (!pagedir_is_accessed(victim->thread->pagedir, victim->vme->vaddr))
    {
      break;
    }
    else
    {
      pagedir_set_accessed(victim->thread->pagedir, victim->vme->vaddr, false);
    }
  }

  if (victim->vme->type == VM_FILE)
  {
    if (pagedir_is_dirty(victim->thread->pagedir, victim->vme->vaddr))
    {
      lock_acquire(&lock_file);
      file_write_at(victim->vme->file, victim->vme->vaddr, victim->vme->read_bytes, victim->vme->offset);
      lock_release(&lock_file);
    }
  }
  else
  {
    victim->vme->swap_slot = swap_out(victim);
    victim->vme->type = VM_ANON;
    victim->vme->is_loaded = false;
  }

  free_page(victim->kaddr);

  return palloc_get_page(flags);
}

struct page *find_page(void *kaddr)
{
  struct page *page;
  struct list_elem *elem, *tail;

  lock_acquire(&lru_list_lock);

  for (elem = list_front(&lru_list), tail = list_tail(&lru_list);
       elem != tail;
       elem = list_next(elem))
  {
    page = list_entry(elem, struct page, lru);
    if (page->kaddr == kaddr)
    {
      lock_release(&lru_list_lock);
      return page;
    }
  }

  lock_release(&lru_list_lock);

  return NULL;
}

struct list_elem *get_next_lru_clock()
{
  return (lru_clock->next == list_head(&lru_list)) ? lru_clock->next : list_begin(&lru_list);
}
