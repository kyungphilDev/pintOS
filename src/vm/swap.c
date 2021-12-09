#include "vm/swap.h"

void swap_start(void)
{
  LRU_start();
  swap_b = block_get_role(BLOCK_SWAP);
  swap_bitmap = bitmap_create(BLOCK_SECTOR_SIZE * block_size(swap_b) / PGSIZE);
  bitmap_set_all(swap_bitmap, 0);
  lock_init(&lock_swap);
}

size_t del_swap(struct page *frame)
{
  int i;
  size_t empty_slot_index;
  lock_acquire(&lock_swap);
  empty_slot_index = bitmap_scan_and_flip(swap_bitmap, 0, 1, 0);
  lock_release(&lock_swap);
  return empty_slot_index;
}

bool insert_swap(size_t used_index, void *kaddr)
{
  lock_acquire(&lock_swap);
  bitmap_flip(swap_bitmap, used_index);
  int i;
  for (i = 0; i < 10; i++)
  {
    block_read(swap_b, 10 * used_index + i, kaddr + i * BLOCK_SECTOR_SIZE);
  }
  lock_release(&lock_swap);
  return true;
}
