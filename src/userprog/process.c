#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "syscall.h"
#include "threads/malloc.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);


/*
	<<< usage of strtok_r >>>
   char s[] = "  String to  tokenize. ";
   char *token, *save_ptr;
   for (token = strtok_r (s, " ", &save_ptr); token != NULL;
		token = strtok_r (NULL, " ", &save_ptr))
	 printf ("'%s'\n", token);
*/

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created.
   Split @param file_name to file name and other arguments. 
   */
tid_t
process_execute (const char *file_name) 
{
	//printf("process_execute\n");
  char *fn_copy;

  ////////// Added /////////
  char temp[128];
  char *cmd_name;			// Only include command line without arguments
  char *save_ptr;			// for strtok_r
  ///////////////////////////

  tid_t tid;


  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */

  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL) {
	  palloc_free_page(fn_copy);
	  return TID_ERROR;
  }
  strlcpy (fn_copy, file_name, PGSIZE);


  // fn_copy is original input, fn_copy should include arguments
  // parsing file_name into cmd_name first. Current file_name is invalid
  strlcpy(temp, file_name, strlen(file_name)+1);
  temp[strlen(file_name)] = '\0';
  cmd_name = strtok_r(temp, " ", &save_ptr);

  if (filesys_open(cmd_name) == NULL) {
	  return -1;
  }

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (cmd_name, PRI_DEFAULT, start_process, fn_copy);

  //sema_down(&thread_current()->sema_sync);

  if (tid == TID_ERROR) {
    palloc_free_page (fn_copy); 
    return tid;
  }


  return tid;
}

/* A thread function that loads a user process and starts it
   running. 
   1. Parse the @param file_name into file_name and arguments
   2. Setup stack with arguments using the following conventions:
   (top -- low address)
   return address (0)
   argc (argument count)
   pointer to start of stack
   pointer to arguments
   word align
   arguments
   (bottom -- high address)   
   */
static void
start_process (void *file_name_)
{
  //printf("start_process.........................\n");

  char *file_name = file_name_;

  ///////// Added /////////
  char* cmd_name;				// name of cmd
  char temp[128];
  char* save_ptr, *token;
  char** argv;
  int argc = 0;
  void** esp;
  /////////////////////////

  struct intr_frame if_;
  bool success;


  //////////////// Parsing ////////////////
  strlcpy(temp, file_name, strlen(file_name)+1);
  temp[strlen(file_name)] = '\0';
  
  for (token = strtok_r(temp, " ", &save_ptr); token != NULL; 
      token = strtok_r(NULL, " ", &save_ptr))
	  argc++;

  strlcpy(temp, file_name, strlen(file_name) + 1);
  temp[strlen(file_name)] = '\0';

  argv = (char**)malloc(sizeof(char*) * argc);
  int i = 0;
  int len = 0;
  for (token = strtok_r(temp, " ", &save_ptr); token != NULL; 
      token = strtok_r(NULL, " ", &save_ptr))
  {
	  argv[i] = token;
	  len += strlen(token) + 1;
	  i++;
  }
  //////////////////////////////////////////
  //printf("argc is: %d", argc);
  //printf("\nfile name_start_process: %s\n", argv[0]);

  cmd_name = argv[0];
  vm_init(&thread_current()->vm);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (cmd_name, &if_.eip, &if_.esp);
  

  /* If load failed, quit. */
  palloc_free_page (file_name);

  if (!success) 
  { 
	  thread_current()->load_success = false;

	  sema_up(&thread_current()->sema_load);
	  //sema_up(&thread_current()->parent->sema_sync);
	  //free(argv);
	  thread_exit();
	  //exit(-1);
  }
  else
  {
	  thread_current()->load_success = true;
	  sema_up(&thread_current()->sema_load);
  }

  ///////////// Set up Stack /////////////
  esp = &if_.esp;
  int j ;
  for (j = argc - 1; j >= 0; j--)		// push arguments to stack
  {
	  //*esp -= (strlen(argv[j]) + 1);
	  //strlcpy(esp, argv[j], strlen(argv[j]) + 1);
    int r;
	  for (r = strlen(argv[j]); r >= 0 ; r--) {
		  //printf("arg len: %d\n", strlen(argv[j]));
		  *esp -= 1;
		  **(char**)esp = argv[j][r];
	  }
	  //*esp -= (strlen(argv[j]) + 1);

	  argv[j] = *esp;						// save address
  }
  int word_align;
  if (len % 4 == 0)
	  word_align = 0;
  else
	  word_align = 4 - (len % 4);
  int a ;
  for (a= word_align; a > 0 ; a--)
  {
	  *esp -= 1;
	  **(uint8_t * *)esp = 0;					// align 4byte
  }


  *esp -= 4;								
  **(uint32_t * *)esp = 0;					// argv[argc+1] with NULL
  int k;
  for (k = argc - 1; k >= 0; k--)		// push argv[]
  {
	  *esp -= 4;
	  **(uint32_t * *)esp = argv[k];
  }

  *esp -= 4;
  **(uint32_t * *)esp = *esp + 4;				// push argv

  *esp -= 4;
  **(uint32_t * *)esp = argc;					// push argc

  *esp -= 4;
  **(uint32_t * *)esp = 0;						// push fake returna address

  ////////////////////////////////////////

  free(argv);
  sema_up(&thread_current()->parent->sema_sync);

  //hex_dump(if_.esp, if_.esp, PHYS_BASE - if_.esp, true);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   Use sema_wait to wait until child process has exited. 
*/
int
process_wait (tid_t child_tid UNUSED) 
{
	struct thread* c = get_child_process(child_tid);
	if (c == NULL) { return -1; }
	if (c->exit_success == true) 
	{ 
		int exit_status = c->exit_status; 
		remove_child_process(c);
		return exit_status;
	}

	sema_down(&c->sema_exit);

	int exit_status = c->exit_status;
	remove_child_process(c);


  return exit_status;
}

/* Free the current process's resources. 
   Resources include file descriptor table and open files and children */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

//  for (int i = (cur->fd_max) - 1; i > 2; i--) {
//	  if (cur->fd_table[i] != NULL) {
//		  close(i);
//	  }
//	  cur->fd_max = cur->fd_max - 1;
//  }
  int i;
  for (i = 0; i < 128; i++) {
	  if (cur->fd_table[i] != NULL) {
		  close(i);
	  }
  }
  file_close(cur->running_file);
  //printf("file closed\n");

  cur->running_file = NULL;

  ////////////////////+++++++++++++++++++///////////////////////////////
  struct thread* c;
  struct list_elem* e;
  for (e = list_begin(&cur->child_list); e != list_end(&cur->child_list); 
       e = list_next(e))
  {
	  c = list_entry(e, struct thread, child_elem);
	  if (c->exit_success == true) process_wait(c->tid);
	  else c->parent = NULL;
  }

  int mmap_id;
  struct mmap_file *mmap_file;
  struct vm_entry* vme;
  struct list_elem* next_e; 
  mmap_id = 0;

  bool vme_is_loaded ;
  bool dirty_bit;

  for (; mmap_id < cur->mmap_id_max; mmap_id++)
    {
      mmap_file = get_mmap_file (mmap_id);
      if (mmap_file) 
      {
        e = list_begin(&mmap_file->vme_list);

        for (; e != list_end(&mmap_file->vme_list);
            e = next_e) 
          {
            next_e = list_next(e);
            vme = list_entry(e, struct vm_entry, mmap_elem);
            vme_is_loaded = vme->is_loaded_to_memory;
            dirty_bit = pagedir_is_dirty(thread_current()->pagedir, vme->va);
            if (vme_is_loaded && dirty_bit) {
              file_write_at (vme->file, vme->va, vme->read_bytes, vme->offset);     
              free_physical_page_frame(vme->va);
            }
            vme->is_loaded_to_memory = false;
            vme = list_entry(e, struct vm_entry, mmap_elem);
            list_remove(e);
            delete_vme(&thread_current()->vm, vme);
          }
        list_remove(&mmap_file->elem);
        free(mmap_file);  
      }
    }
  //////////////////////////////////////////////////////////////////////
  //printf("mmap closed\n");

  //printf("going into destroy vm\n");
  //////////////////////////////////////////P3
  /* Delete hash table and vm_entries using destroy_vm()*/
  destroy_vm(&thread_current()->vm);
  //////////////////////////////////////////P3
  //printf("destroying vm complete\n");


  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  if (cur->parent == NULL) {
	  //printf("No parent. Free resources\n");
	  //palloc_free_page(cur);
  }
  //palloc_free_page(cur);
  //printf("exiting\n");

}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  struct lock load_lock;
  lock_init(&load_lock);

  lock_acquire(&load_lock);
  /* Open executable file. */
  if (true){ 
    file = filesys_open (file_name);
    if (file == NULL) 
      {
      lock_release(&load_lock);
        //printf ("load: %s: open failed\n", file_name);
        goto done; 
      }
  }
  t->running_file = file;
  file_deny_write(file);
  lock_release(&load_lock);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      //printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      //Create vm_entry using malloc()
      struct vm_entry* vme = (struct vm_entry*) malloc(sizeof(struct vm_entry));
	  if (vme == NULL)
		  return false;

      //Set vm_entry members 
      vme->file_type = VM_BIN;
      vme->file = file;
      vme->offset = ofs;
      vme->write_permission = writable;
      vme->read_bytes = page_read_bytes;
      vme->zero_bytes = page_zero_bytes;
      vme->is_loaded_to_memory = false;
      vme->va = upage; 
      vme->swap_slot = 0;

      //Add vm_entry to hash table
      insert_vme(&thread_current()->vm, vme);
	  //printf("load segment vme inserted: %x\n", upage);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  struct page *kpage;
  uint8_t *upage;
  bool success = false;
  struct vm_entry* vme;

  vme = (struct vm_entry*) malloc(sizeof(struct vm_entry));
  if (vme == NULL)
  {
	  return false;
  }

  kpage = allocate_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
	  //printf("phys base: %x\n", PHYS_BASE);
	  //printf("pgsize: %u\n", PGSIZE);
      //push_page_to_table(kpage);
      upage = ((uint8_t *) PHYS_BASE) - PGSIZE;
      success = install_page (upage, kpage->physical_addr, true);
      if (success) 
	  {
		  *esp = PHYS_BASE;

		  ////////// Added in P3 start /////////
		  //initialize vm_entry for 4KB stack 
		  //vme = malloc(sizeof(struct vm_entry));

		  //set members of the vm_entry 
		  //TODO: va, write_permission, is_loaded_to_memory unclear
      kpage->vme = (struct vme* ) malloc (sizeof(struct vm_entry));
      kpage->vme->file_type = VM_SWAP;
		  kpage->vme->va = upage;                
		  kpage->vme->write_permission = true;    
		  kpage->vme->is_loaded_to_memory = true;
      kpage->vme->swap_slot = 0;

		  //insert created vm_entry into vm hash table of thread 
		  insert_vme(&thread_current()->vm, kpage->vme);
		  //printf("setup_stack vme insterted: %x\n", upage);
		  ////////// Added in P3 end /////////

	  } 
	  else 
	  {
		  free_physical_page_frame(kpage);
      free(vme);
		  return false;
	  }

    }

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}


/* Find child process by pid and return it
	if cannot find process, return null */
struct thread*
get_child_process(int pid)
{
	struct thread* t = thread_current();
	struct thread* c;
	struct list_elem* e;
	//printf("trying get child process... \n");
	for (e = list_begin(&t->child_list); 
  e != list_end(&t->child_list); e = list_next(e))
	{
		c = list_entry(e, struct thread, child_elem);
		if (c->tid == pid) {
			//printf("get child process success! \n");
			return c;
		}
	}
	//printf("\n Cannot find child process %d \n", pid);
	return NULL;
}

/* Delete child process */
void
remove_child_process(struct thread* c)
{
	//printf("fuck");
	list_remove(&c->child_elem);

	palloc_free_page(c);
}

/**
 * @param vme   vme that page fault occurred 
 * @returns     whether page fault was successfuly handled 
 * 
 * Handles page fault originated from @file excetion.c and returns the result 
 * of page fault handling in boolean form. 
 * 
 * Firstly, allocates new page; then based on the file type of the vme, 
 * do appropriate operations. 
 */ 
bool 
page_fault_handler (struct vm_entry* vme) 
{
  struct page* kaddr; //address of physical page 
  bool res;  
  //printf("page_fault_handler!!\n");
  kaddr = allocate_page (PAL_USER);
  if (kaddr == NULL) {
    return false;
  }
  kaddr->vme = vme;
  
  switch(kaddr->vme->file_type) {
    case VM_BIN:  
    case VM_FILE:
      if (!load_file(kaddr->physical_addr, vme)) {
        free_physical_page_frame(kaddr->physical_addr);
        return false;
      }
      /* printf("installing up 0x%x to vp 0x%x\n", 
              vme->va, kaddr->physical_addr); */
      res = install_page(vme->va, kaddr->physical_addr, vme->write_permission);
      if (!res) {
		    return false;
      }
      kaddr->vme->is_loaded_to_memory = true;
      push_page_to_table(kaddr);
      break;
    case VM_SWAP:
       swap_in (kaddr->physical_addr, vme->swap_slot);
       res = install_page (vme->va, kaddr->physical_addr,
                           vme->write_permission);
       kaddr->vme->is_loaded_to_memory = true;
       push_page_to_table(kaddr);
       
      break;
    default:
      ASSERT(false); // should never reach 
      break;
  }
  return res;
}

/**
 * @param   addr  address to check whether to grow stack 
 * @returns       whether growth happen
 * Grow stack if @param addr is applicable.
 */ 
bool
grow_stack(void* addr)
{
  void* page_addr;
  struct page* kpage;

	/* No heuristic check here, check heuristic validity before using this function */
  page_addr = pg_round_down(addr);

	/* stack should be smaller than 8MB */
	if (page_addr < USER_STACK_BOTTOM) {
		return false;
	}

	//kpage = alloc page()
	 kpage = allocate_page (PAL_USER);


	/* creat and init vm_entry of page */
	kpage->vme = (struct vm_entry*) malloc(sizeof(struct vm_entry));
	if (kpage->vme == NULL) {
		return false;
	}

	kpage->vme->file_type = VM_SWAP;
	kpage->vme->write_permission = true;
	kpage->vme->is_loaded_to_memory = true;
	kpage->vme->va = page_addr;
  kpage->vme->swap_slot = 0;

	insert_vme(&thread_current()->vm, kpage->vme);

	if (!install_page(page_addr, kpage->physical_addr, true)) {
		return false;
	}

}