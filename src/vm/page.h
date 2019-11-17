#include <hash.h>
#include <debug.h>
#include <stdint.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

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
  
  struct hash_elem elem; 
};

bool insert_vme (struct hash* vm, struct vm_entry* vme);
bool delete_vme (struct hash* vm, struct vm_entry* vme);
struct vm_entry* find_vme(void* va);
void destroy_vm (struct hash* vm);
void hash_destroy_action_func (struct hash_elem* e, void* aux UNUSED);

bool load_file(void* kaddr, struct vm_entry* vme);
