#include "vm/page.h"
#include "userprog/process.h"

static unsigned vm_hash_func(const struct hash_elem* e, void* aux);
static bool vm_hash_less_func (const struct hash_elem* a, 
                               const struct hash_elem* b,
                               void* AUX UNUSED);
static struct list_elem* find_clock_victim();

struct list frame_table;
struct lock frame_table_access_lock;
struct list_elem* clock_victim;

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
 * @returns list_elem* of the next victim to evict 
 * 
 * Returns the next victim based on the clock algorithm. If victim is NULL, 
 * get the first elem of the frame_table list 
 */ 
static struct list_elem* 
find_clock_victim() {
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