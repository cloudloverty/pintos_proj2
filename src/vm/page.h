#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <debug.h>
#include <stdint.h>
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
//#include "userprog/process.h"
#include <string.h>

#define VM_BIN        0 //Page of ELF format file 
#define VM_FILE       1 //Page of General File 
#define VM_SWAP       2 //Page of Swap Area 

struct vm_entry {
  uint8_t file_type;        //type of file

  void* va;                 //virtual address 
  
  bool write_permission;    //whether writing to that address is permitted 
  bool is_loaded_to_memory; //whether vp is loaded to physical memory 

  struct file* file;        //pointer to file mapped to the virtual address 

  size_t offset;            //where to start reading in file
  size_t read_bytes;    //number of bytes readable 
  size_t zero_bytes;        // numbetr of byets to 0 out
  
  struct hash_elem elem; //elem for hash table of thread 
  struct list_elem mmap_elem; //for elem of vme_list of mmap_file
};

struct mmap_file {
  int mapping_id; //mapping id returned on successful completion of mmap()
  struct file* file; //mapped file
  struct list_elem elem; //for mmap_list of mmap files
  struct list vme_list; //for managing all vm_entry mapping to mmap_file
};

struct page {
  void* physical_addr; //physical address of the page 
  struct vm_entry* vme; //the vm_entry of the logical address 
  struct thread* page_thread; //thread structure that the page is belonged to 
  struct list_elem lru; // list_elem for the lru list
};

void vm_init (struct hash* vm); 
bool insert_vme (struct hash* vm, struct vm_entry* vme);
bool delete_vme (struct hash* vm, struct vm_entry* vme);
struct vm_entry* find_vme(void* va);
void destroy_vm (struct hash* vm);
void hash_destroy_action_func (struct hash_elem* e, void* aux UNUSED);

bool load_file(void* kaddr, struct vm_entry* vme);

void init_frame_table(void);
void free_physical_page_frame(void* addr);
void push_page_to_table(struct page* page_frame);
struct page* allocate_page (enum palloc_flags flags);
struct page* find_page_from_frame_table(void* addr);
void remove_page_from_table (struct page* page);

void vm_swap_init();
void vm_swap_in();
void vm_swap_out();

#endif