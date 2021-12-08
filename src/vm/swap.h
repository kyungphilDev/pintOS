#ifndef PAGE_H_
#define PAGE_H_

#include <stdio.h>
#include <bitmap.h>
#include "vm/page.h"
#include "devices/block.h"
#include "threads/vaddr.h"

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

struct block;
struct bitmap;

struct block *swap_block;
struct bitmap *swap_slot_bitmap;
struct lock swap_lock;

void swap_init(void);
size_t swap_out(struct page *frame);
bool swap_in(size_t used_index, void *kaddr);

#endif
