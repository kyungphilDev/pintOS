#ifndef PAGE_H_
#define PAGE_H_

#include <stdio.h>
#include <bitmap.h>
#include "vm/page.h"
#include "devices/block.h"
#include "threads/vaddr.h"

struct bitmap;
struct block;
struct bitmap *swap_bitmap;
struct block *swap_b;
bool insert_swap(size_t used_index, void *kaddr);
size_t del_swap(struct page *frame);
void swap_start(void);
struct lock lock_swap;

#endif
