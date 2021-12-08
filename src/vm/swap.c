#include "vm/swap.h"

void swap_init(void)
{
  lru_list_init();
  swap_block = block_get_role(BLOCK_SWAP);
  swap_slot_bitmap = bitmap_create(BLOCK_SECTOR_SIZE * block_size(swap_block) / PGSIZE);
  bitmap_set_all(swap_slot_bitmap, 0);
  lock_init(&swap_lock);
}

size_t swap_out(struct page *frame)
{
  int i;
  size_t empty_slot_index;

  lock_acquire(&swap_lock);

  empty_slot_index = bitmap_scan_and_flip(swap_slot_bitmap, 0, 1, 0);

  for (i = 0; i < SECTORS_PER_PAGE; i++)
  {
    block_write(swap_block, SECTORS_PER_PAGE * empty_slot_index + i, frame->kaddr + i * BLOCK_SECTOR_SIZE);
  }

  frame->vme->swap_slot = empty_slot_index;
  lock_release(&swap_lock);
  return empty_slot_index;
}

bool swap_in(size_t used_index, void *kaddr)
{
  int i;

  lock_acquire(&swap_lock);

  if (bitmap_test(swap_slot_bitmap, used_index) == 0)
  {
    return false;
  }
  bitmap_flip(swap_slot_bitmap, used_index);

  for (i = 0; i < SECTORS_PER_PAGE; i++)
  {
    block_read(swap_block, SECTORS_PER_PAGE * used_index + i, kaddr + i * BLOCK_SECTOR_SIZE);
  }
  lock_release(&swap_lock);
  return true;
}
