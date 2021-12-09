#ifndef FRAME_H_
#define FRAME_H_
#include <list.h>
#include "threads/synch.h"
#include "vm/page.h"

struct list lru_list;
struct lock lock_LRU;
struct list_elem *LRU_c = NULL;
void *free_page_LRU(enum palloc_flags flags);
struct list_elem *get_LRU_c();
struct page *find_page(void *kaddr);
void LRU_start(void);
void LRU_add(struct page *page);
void LRU_del(struct page *page);

#endif
