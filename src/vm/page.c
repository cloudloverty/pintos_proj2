

#include "vm/page.h"
#include "userprog/process.h"
#include "devices/block.h"

static unsigned vm_hash_func(const struct hash_elem* e, void* aux);
static bool vm_hash_less_func (const struct hash_elem* a, 
                               const struct hash_elem* b,
                               void* AUX UNUSED);
static struct list_elem* find_clock_victim();

struct list frame_table;

struct lock frame_table_access_lock;
struct lock swap_space_lock;

struct list_elem* clock_victim;

struct bitmap* swap_space;

/**
 * @param vm Hash table to initializae 
 * Initializes hash table vm of process 
 * Used in start_process of process.c 
 */ 
void 
vm_init (struct hash* vm) 
{
  //bool hash_init(struct hash* h, hash_hash_func * hash, hash_less_func * less, void* aux)

  bool hash_table_init_res; //return value of hash_init function 
  hash_table_init_res = hash_init(vm, vm_hash_func, vm_hash_less_func, NULL); 

  ASSERT(hash_table_init_res != false); 
}


/**
 * @param   e hash element to search for 
 * @returns   hash value 
 * Computes and returns the hash value for hash element E, given
 * auxiliary data AUX. 
 */ 
static unsigned 
vm_hash_func (const struct hash_elem* e, void* aux UNUSED) 
{
  int hash_for_va; //hash value for va
  struct vm_entry* vme; //struct that hash_elem e is in 
  
  vme = (struct vm_entry*) hash_entry(e, struct vm_entry, elem);
  hash_for_va = hash_int(vme->va);

  return hash_for_va;
}

/**
 * @param   a hash_elem to compare with b 
 * @param   b hash_elem to compare with a 
 * @returns   true if a is less than b, false otherwise
 * 
 * Compares the value of two hash elements A and B, given
  * auxiliary data AUX.  Returns true if A is less than B, or
  * false if A is greater than or equal to B. 
 */ 
static 
bool vm_hash_less_func (const struct hash_elem* a, 
                        const struct hash_elem* b,
                        void* AUX UNUSED) 
{
  struct vm_entry* vme1; //struct that hash_elem a is in 
  struct vm_entry* vme2; //struct that hash_elem b is in 
  bool res;

  vme1 = (struct vm_entry*) hash_entry(a, struct vm_entry, elem);
  vme2 = (struct vm_entry*) hash_entry(b, struct vm_entry, elem);

  res = vme1->va < vme2->va;
  return res;
}

/**
 * @param vm    the hash table to insert @param vme into 
 * @param vme   the vm_entry to insert into @param vm
 * @returns     whether insert was successful or not 
 * 
 * Insert @param vme into @param vm. 
 * Return true if insert was sucessful, and false if insert wasn't sucessful 
 * 
 */ 
bool 
insert_vme (struct hash* vm, struct vm_entry* vme) 
{
  hash_insert(vm, &(vme->elem));

  return true; 

}

/**
 * @param vm    the hash table to delete @param vme into 
 * @param vme   the vm_entry to delete into @param vm
 * @returns     whether delete was successful or not 
 * 
 * Delete @param vme from @param vm. 
 * Return true if delete was sucessful, and false if delete wasn't sucessful 
 */ 
bool 
delete_vme(struct hash* vm, struct vm_entry* vme) 
{
  struct hash_elem * res; //stores return value of hash_delete() 
  
  res = hash_delete(vm, &(vme->elem));
  
  return (res != NULL);
}

/** 
 * @param va    virtual address
 * @returns     the vm_entry (i.e. page) that corresponds to the va
 * 
 * Find and return the vm_entry that corressponds to @param va
 */ 
struct vm_entry* 
find_vme(void* va) 
{
  void* start_virtual_page;
  struct hash_elem* e; 
  struct vm_entry vme; //struct that hash_elem e is in 
  //printf("enter find_vme. virtual address is %x\n", va);
  start_virtual_page = pg_round_down(va);
  //printf("virtual page is %x\n", start_virtual_page);
  vme.va = start_virtual_page; 
  //printf("try to find hash\n");
  e = hash_find(&thread_current()->vm, &(vme.elem)); 
  //printf("hash found\n");

  if (e == NULL) {
	  //printf("cannot find vme: %d\n", (int)va);
    return NULL; 
  } else {
    return  hash_entry(e, struct vm_entry, elem);
  } 
}

/**
 * @param vm  
 * 
 * Deallocate the bucket list of @param vm and all vm_entry associated with vm
 */ 
void 
destroy_vm(struct hash* vm) 
{
  hash_destroy(vm, hash_destroy_action_func);
}

/** 
 * @param e   hash_elem to destroy
 * @param aux UNUSED
 * 
 * Auxillary function used for hash_destroy  
 */ 
void 
hash_destroy_action_func (struct hash_elem* e, void* aux UNUSED) 
{
  struct vm_entry* vme; //struct that hash_elem e is in 
  void* start_of_page; 
  
  vme = (struct vm_entry*) hash_entry(e, struct vm_entry, elem);
  free (hash_entry (e, struct vm_entry, elem));
  ///*if page is loaded to memory, free page and change page in PDE */
  //if (vme->is_loaded_to_memory == true) { 
  //  start_of_page = pg_round_down(vme->va);
  //  palloc_free_page(start_of_page);
  //  pagedir_clear_page(thread_current()->pagedir, start_of_page);
  //}
  //free(vme);
}

/**
 * @param kaddr   physical address to load the page 
 * @param vme     vm_entry 
 * Load the file to physical page in @param kaddr 
 * Use memset to set remainding bytes to 0, if necessary.  
 */
bool 
load_file(void* kaddr, struct vm_entry* vme) 
{
  off_t actual_read; 

  actual_read = file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset);
  memset (kaddr + vme->read_bytes, 0, vme->zero_bytes);

  if (actual_read != vme->read_bytes) {
    return false;
  }
  return true; 
}

/**
 * Initializes the frame table and the frame_table_access_lock
 */ 
void 
init_frame_table(void) 
{
  list_init(&frame_table);
  lock_init(&frame_table_access_lock);
}

/** 
 * Initializes the swap space bit map and the swap_space_lock
 * 
 * @param size_of_swap_space The size to initialize the swap space.
 */ 
void 
init_swap_space(size_t size_of_swap_space)
{
  swap_space = bitmap_create(size_of_swap_space);
  bitmap_set_all(swap_space, true);
  lock_init(&swap_space_lock); 
}

/**
 * @param flags Flags used for palloc
 * 
 * Allocate page frame from using palloc_get_page() 
 */
struct page*
allocate_page (enum palloc_flags flags)
{
  void* new_page;
  struct page* new_page_struct;

  new_page = palloc_get_page(flags);
  new_page_struct = (struct page*) malloc (sizeof (struct page));

  new_page_struct->page_thread = thread_current();
  
  while (new_page == NULL) {
    reap_lru();
    new_page = palloc_get_page(flags);
  }

  new_page_struct->physical_addr = new_page; 

  push_page_to_table(new_page_struct);

  return new_page_struct;
} 

/**
 * @param addr address to freee 
 * 
 * Free the physical page frame of the @param addr by searching in 
 * the lru list.
 */ 
void
free_physical_page_frame(void* addr) 
{
  struct page* page;

  lock_acquire(&frame_table_access_lock);
  page = find_page_from_frame_table(addr);
  list_remove(&page->lru);
  pagedir_clear_page (page->page_thread->pagedir, page->vme->va);
  palloc_free_page(page->physical_addr);

  free(page);
  lock_release(&frame_table_access_lock);
}

/**
 * @param  page physical page frame to add to table
 * 
 * Adds page to the frame_table list 
 */ 
void 
push_page_to_table(struct page* page_frame) 
{
  lock_acquire(&frame_table_access_lock);
  list_push_back(&frame_table, &page_frame->lru);
  lock_release(&frame_table_access_lock);
}

/**
 * @param   page physical page frame to delete from frame table 
 * 
 * Delete @param page from frame_table 
 */ 
void 
remove_page_from_table (struct page* page) 
{
  lock_acquire(&frame_table_access_lock);
  list_remove(&page->lru);
  lock_release(&frame_table_access_lock);
}

/**
 * @param   addr  addr to look for in the frame table 
 * 
 * Find page of physical address @param addr. If there is no match, return 
 * NULL.
 */
struct page*
find_page_from_frame_table(void* addr) 
{
  struct list_elem* e;
  struct page* page;

  e = list_begin(&frame_table);
  for (; e!= list_end(&frame_table); e = list_next(e)) {
    page = list_entry(e, struct page, lru);
    if (page->physical_addr == addr)
      return page; 
  }
  return NULL; 
} 

/**
 * @param addr  Address to swap in 
 * @param index Index in swap space to swap in.
 * 
 * Swap in contents in @param addr to @param index of swap space. 
 */ 
void 
vm_swap_in (void* addr, size_t index)
{
  int i;  
  size_t swap_index;
  struct block* block;

  block = block_get_role(BLOCK_SWAP);

}

/**
 * @param addr  Address to swap out 
 * 
 * Swap contents out from @param addr to swap space. 
 */ 
size_t 
vm_swap_out(void* addr) 
{
  size_t i;

  i = 0;

  for (; i < PGSIZE / BLOCK_SECTOR_SIZE; i++) {

  }

}

/**
 * @return evicted victim by the clock algorithm 
 * 
 * Evict a victim from the LRU list per the clock algorithm.
 */ 
void* 
evict_clock_victim(void) 
{
  struct list_elem* clock_victim;
  struct page* page;
  bool access_status;

  while (true) {
    clock_victim = find_clock_victim();
    page = list_entry(clock_victim, struct page, lru);
    if (page->vme != NULL) {
      access_status = pagedir_is_accessed(thread_current()->pagedir, 
                                          page->vme->va);
      if (access_status) {
        pagedir_set_accessed(thread_current()->pagedir, 
                             page->vme->va, false);
      } else {
        break;
      }
    }
  }
  list_remove(clock_victim);
  return page;  
}

/** 
 * Reap LRU entries such that palloc_get_page works
 */ 
void 
reap_lru(void)
{
  struct page* page;
  bool dirty_bit;

  page = evict_clock_victim();
  dirty_bit = pagedir_is_dirty(page->page_thread->pagedir, page->vme->va);
  
  switch(page->vme->file_type) {
    case VM_BIN:
      if (dirty_bit) {
        page->vme->swap_slot = vm_swap_out(page->physical_addr);
        page->vme->file_type = VM_SWAP;
      }
      break;  
    case VM_FILE:
      if (dirty_bit) {
        file_write_at (page->vme->file, page->vme->va, page->vme->read_bytes,
                       page->vme->offset);
      }
      break;
    case VM_SWAP:
      if (dirty_bit) 
        page->vme->swap_slot = vm_swap_out(page->physical_addr);
      break;
  }

  pagedir_clear_page (page->page_thread->pagedir, page->vme->va);
  page->vme->is_loaded_to_memory = false;
  palloc_free_page (page->physical_addr);
  free (page);

}

/** 
 * @returns list_elem* of the next victim to evict 
 * 
 * Returns the next victim based on the clock algorithm. If victim is NULL, 
 * get the first elem of the frame_table list 
 */ 
static struct list_elem* 
find_clock_victim(void) 
{
  if (clock_victim == NULL) { 
    if(list_empty(&frame_table)) {
      clock_victim = NULL;
    } else {
      clock_victim = list_begin(&frame_table);
    } // end of clock_victim == NULL
  } else {
    clock_victim = list_next(clock_victim);
    if (clock_victim == NULL)
      clock_victim = list_begin(&frame_table);
  }
  return clock_victim;
}
