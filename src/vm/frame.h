#ifndef FRAME_H_
#define FRAME_H_

#include <list.h>
#include "threads/synch.h"
#include "vm/page.h"

struct list lru_list;
struct lock lru_list_lock;
struct list_elem *lru_clock = NULL;

void lru_list_init(void);
void add_page_to_lru_list(struct page *page);
void del_page_from_lru_list(struct page *page);
void *try_to_free_pages(enum palloc_flags flags);
struct page *find_page(void *kaddr);
struct list_elem *get_next_lru_clock();

#endif
