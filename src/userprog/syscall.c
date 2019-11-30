#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "vm/page.h"


static void syscall_handler (struct intr_frame *);
static struct vm_entry* check_add_valid(void* addr, void* esp);
static struct vm_entry* check_add_valid_simple(void* addr);
static void check_buffer_validity(void* buffer, unsigned size, 
                                  void* esp, bool to_write);
static void check_valid_string(const void* str, void* esp);
void set_arg(void* esp, uint32_t* argv, int argc);

/**
 * Initializies system call system by initializing filesys_lock for 
 * synchronization between files and the interrupt handler   
 */ 
void
syscall_init (void) 
{
	lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/** 
 * @param f intr_frame which stores the esp of the stack 
 * 
 * Handles system calls based on system call number using switch statements.
 * First, get system call number and arguments from f->esp ~ f->esp + 4 * argc
 * Then, check validity of arguments 
 * Then, switch to appropriate syscall handler based on syscall number. 
 * 
 */ 
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	//printf("syscall_handler\n");
	//printf("esp address is %x\n", f->esp);
	//hex_dump(f->esp, f->esp, 96, true);

  check_add_valid((uint32_t)f->esp, f->esp);
  uint32_t syscall_num = *(uint32_t*)f->esp;
  //printf("syscall number: %d\n", syscall_num);
  uint32_t argv[3];

  switch (syscall_num) {
  case SYS_HALT: //0
	  halt();
	  break;

  case SYS_EXIT: //1
	  set_arg(f->esp, argv, 1);
	  exit((int)*(uint32_t*)argv[0]);
	  break;

  case SYS_EXEC: //2
	  set_arg(f->esp, argv, 1);
	  check_valid_string((const char*) * (uint32_t*)argv[0], f->esp);
	  f->eax = exec((const char*) * (uint32_t*)argv[0]);
	  break;

  case SYS_WAIT: //3
	  set_arg(f->esp, argv, 1);
	  f->eax = wait((pid_t) * (uint32_t*)argv[0]);
	  break;

  case SYS_CREATE: //4
	  set_arg(f->esp, argv, 2);
	  check_valid_string((const char*) * (uint32_t*)argv[0], f->esp);
	  f->eax = create((const char*) * (uint32_t*)argv[0], 
                    (unsigned) * (uint32_t*)argv[1]);
	  break;

  case SYS_REMOVE: //5
	  set_arg(f->esp, argv, 1);
	  check_valid_string((const char*) * (uint32_t*)argv[0], f->esp);
	  f->eax = remove((const char*) * (uint32_t*)argv[0]);
	  break;

  case SYS_OPEN: //6
	  set_arg(f->esp, argv, 1);
	  check_valid_string((const char*) * (uint32_t*)argv[0], f->esp);
	  f->eax = open((const char*) * (uint32_t*)argv[0]);
	  break;

  case SYS_FILESIZE: //7
	  set_arg(f->esp, argv, 1);
	  f->eax = filesize((int) * (uint32_t*)argv[0]);
	  break;

  case SYS_READ: //8
	  set_arg(f->esp, argv, 3);
	  check_buffer_validity((void*) * (uint32_t*)argv[1], 
                          (unsigned) * (uint32_t*)argv[2], f->esp, true);
	  f->eax = read((int) * (uint32_t*)argv[0], 
                  (void*) * (uint32_t*)argv[1], 
                  (unsigned) * (uint32_t*)argv[2]);
	  break;

  case SYS_WRITE: //9
	  set_arg(f->esp, argv, 3);
	  check_buffer_validity((void*) * (uint32_t*)argv[1], 
                          (unsigned) * (uint32_t*)argv[2], f->esp, false);
	  f->eax = write((int)* (uint32_t*)argv[0], 
                   (const void*)* (uint32_t*)argv[1], 
                   (unsigned)* (uint32_t*)argv[2]);
	  break;

  case SYS_SEEK:
	  set_arg(f->esp, argv, 2);
	  seek((int) * (uint32_t*) argv[0], (unsigned) * (uint32_t*) argv[1]);
	  break;

  case SYS_TELL:
	  set_arg(f->esp, argv, 1);
	  f->eax = ((int) * (uint32_t*)argv[0]);
	  break;

  case SYS_CLOSE:
	  set_arg(f->esp, argv, 1);
	  close((int) * (uint32_t*)argv[0]);
	  break;

  case SYS_MMAP:
    set_arg(f->esp, argv, 2);
	  f->eax = mmap((int) * (uint32_t*)argv[0], (void*) * (uint32_t*)argv[1]);
	  break;
  
  case SYS_MUNMAP:
    set_arg(f->esp, argv, 1);
	  munmap((int) * (uint32_t*)argv[0]);
	  break;
  }
}

/** 
 * @param esp   stack pointer 
 * @param argv  argument array
 * @param argc  argument count
 * 
 * Do validity checking of address of all arguments. 
 * Set up the arguments by retrieving the arguments from the stack denoted by
 * @param esp and putting into @param argv for @param argc number of times. 
 */ 
void 
set_arg(void* esp, uint32_t* argv, int argc)
{
	//printf("esp point to %d\n", (int) * (uint32_t*)(esp));
	//printf("esp address is %x\n", esp);
	check_add_valid_simple(esp);
  int i;
	esp += 4;							// skip syscall number
	for (i = 0; i < argc; i++)
	{
		//printf("%d roop\n", i);
		//printf("esp address is %x\n", esp);
		check_add_valid_simple(esp+3);
		argv[i] = (uint32_t*) esp;
		
		//printf("esp point to %d\n", (int) * (uint32_t*)(esp));
		//printf("arg[%d] is %d\n", i, (int) * (uint32_t*)argv[i]);

		esp += 4;
	}
}
/**
 * @param addr address of pointer to check validity
 * @returns    vm_entry, if applicable 
 * 
 * Checks the validity of @param addr. 
 */ 
static struct vm_entry* 
check_add_valid(void* addr, void* esp)
{
  struct vm_entry* vme; 
  //printf("check_add_valid with %p\n", addr);

	if ((uint32_t)addr < 0x8048000 || (uint32_t)addr >= 0xc0000000)
	{
		//printf("check_add_valid 1: %x\n", addr);
		exit(-1);
	}
  
  vme = find_vme(addr);

  //if (!vme) {
	 // return vme;
  //}
  //else if (USER_STACK_GROW_LIMIT >= esp - addr) {	
    // valid address -> expand stack
	 // if (!grow_stack(addr)) {
		//  printf("stack grow fail\n");
		//  exit(-1);
	 // }
  //}

  if (vme == NULL) {
	  if (USER_STACK_GROW_LIMIT >= esp - addr && grow_stack(addr)) {
		  vme = find_vme(addr);
		  goto done;
	}
	//printf("check_add_valid 2\n");
    exit(-1);
  }
  
  done:
  return vme;
}

static struct vm_entry*
check_add_valid_simple(void* addr)
{
	struct vm_entry* vme;

	if ((uint32_t)addr < 0x8048000 || (uint32_t)addr >= 0xc0000000)
		exit(-1);

	vme = find_vme(addr);
	if (vme == NULL)
		exit(-1);

	return vme;
}

/**
 * @param buffer 
 * @param size
 * @param esp 
 * @param to_write  check whether buffer is wriable 
 * 
 *  Function to check whether vm_entry in buffer is valid 
 */ 
static void 
check_buffer_validity(void* buffer, unsigned size, 
                      void* esp, bool to_write) 
{ 
  struct vm_entry* vme;
  void* buffer_buffer = buffer;
  //printf("param status, %p, %d", buffer, size);

  while (size > 0) {
    //printf("check_buffer_validity %p, %u\n", buffer_buffer, size);
    vme = check_add_valid(buffer_buffer, esp);

      //check whether vm_entry exisits, and if it exists, check read-write 
      //permission
    if (vme == NULL) 
    {
	  //should call grow_stack?
      //printf("check_buffer_validity 1\n");
      exit(-1);
    }
      
    if (to_write && vme->write_permission == false) 
    {
      //printf("check_buffer_validity 2\n");
      exit(-1);
    }
    if (vme->is_loaded_to_memory == false ) 
      page_fault_handler(vme);
    buffer_buffer++;
    size--;
    //printf("check_buffer_validity success\n", buffer);

  }
}

/** 
 * @param str   str to check validity 
 * @param esp   
 * 
 * Function that verifies whether the address value of the string is valid
 */ 
static void 
check_valid_string(const void* str, void* esp) 
{
  const void* str_str = str;

  while (*((char*)str_str) != NULL)
  {
    //printf("checking valid string, %p\n", str_str);
	  check_add_valid(str_str, esp);
	  str_str++;
  }
 
}

/**
 * Terminates Pintos by calling shutdown_power_off().
 * This should be seldomly used as information such as deadlock
 * sitatuions can be lost.
 */ 
void		//0
halt(void)
{
	shutdown_power_off();
}

/** 
 * @param status status of the program 
 * 
 * Terminates the current user program, returning @param status to the 
 * kernel. If the process's parent <wait>s for it, this is the status 
 * that will be returned. 
 * 
 * Conventionally, a status of 0 indicates success, and nonzero values 
 * indicate errors 
 */
void		//1
exit(int status)
{
	//printf("\n\ntry to exit with %d\n", status);
	struct thread* t = thread_current();
	//printf("thread name is %s\n", t->name);
	t->exit_status = status;
  int i;
	for ( i = 3; i < 128; i++) {
		if (t->fd_table[i] != NULL) {
			close(i);
		}
	}
	file_close(t->running_file);
	t->running_file = NULL;

	printf("%s: exit(%d)\n", t->name, status);
	thread_exit();
}

/**
 * @param cmd_line Command line arguments 
 * @return New procees's pid | -1 if error 
 * 
 * Runs the executable whose name is given in cmd_line, passing any given 
 * arguments. @return new process's pid or -1 if error. 
 * 
 * Parent process cannot return from the exec until it knows whether the child
 * process successfully loaded its exectuable;
*/
pid_t		//2
exec(const char* cmd_line)
{
  //printf("cmd_line of exec, %s\n", cmd_line);
	//check_add_valid_simple(cmd_line);


	//if (*cmd_line == NULL) exit(-1);
	//return process_execute(cmd_line);
	//printf("exec. process_execute\n");
	tid_t cpid = process_execute(cmd_line);

	if (cpid == -1 || cpid == TID_ERROR) return -1;

	struct thread* c = get_child_process(cpid);
	//printf("exec. sema_down for sema_load\n");
	sema_down(&c->sema_load);

	if (!c->load_success)
	{
		remove_child_process(c);
		return -1;
	}
	else
		return cpid;

}

/** 
 * @param pid child process pid
 * @return exit status of the child 
 * Wait until child process @param pid exits. Returns the exit status of the 
 * child. However, the wait() function can immediately @return -1 if calling
 * double wait on an already waiting child; child has been exited by kernel; 
 * or if pid is not a direct child of calling process.
 */ 
int			//3
wait(pid_t pid)
{
	//printf("\nwait for: pid %d\n", (int)pid);
	struct thread* c = get_child_process(pid);

	if (c == NULL) return -1;
	//printf("child pid is %d\n", c->tid);
	//printf("getChild at syscall done\n");


	int exit_status = process_wait(c->tid);

	//remove_child_process(c);
	//printf("return exit_status: %d\n", exit_status);
	return exit_status;
}

/**
 * @param file          Filename
 * @param initial_size  initial size of file 
 * @return true if successful, false if unsuccessful. 
 * Create a new file called @param file initially @param initial_size
 */
bool		//4
create(const char* file, unsigned initial_size)
{
	//check_add_valid(file);
  bool res;

	if (*file == NULL) exit(-1);
  lock_acquire (&filesys_lock);
	res = filesys_create(file, initial_size);
  /*   struct file* c_file = filesys_open(file);
  printf("allocated file to %p with %d status\n",  c_file, res);
  filesys_close(c_file); */
  lock_release (&filesys_lock);
  return res;
  
}


/**
 * @param file Filename
 * @return true if successful, false otherwise 
 * Remove a file named @param file. If removing an open file, follow the UNIX
 * semantics of removing an open file. 
 */ 
bool		//5
remove(const char* file)
{
	//check_add_valid(file);

	if (*file == NULL) exit(-1);
	return filesys_remove(file);
}

/** 
 * @param file filename
 * @returns fd as unsigned int if open is successful, or -1 if error 
 * 
 * Opens the file called @param file. Returns a nonegative integer handle 
 * called a "file descriptior" (fd), or -1 if file cannot be opened 
 */
int			//6
open(const char* file)
{
	//check_add_valid(file);
	if (file == NULL) return -1;

	lock_acquire(&filesys_lock);

	struct file* open_file = filesys_open(file);
	if (open_file == NULL) {
		lock_release(&filesys_lock);
		return -1;
	}
	else
	{
		int fd = new_file(open_file);
		lock_release(&filesys_lock);
		return fd;
	}
}

/**
 * @param fd file descriptior
 * @returns the size of file, in int
 * 
 * Returns the filesize whose file descriptor is denoted by @param fd
 */
int			//7
filesize(int fd)
{
	struct file* f = get_file(fd);
	if (f == NULL) return -1;

	return file_length(f);
}

/** 
 * @param fd     file descriptor 
 * @param buffer buffer to read into 
 * @param size   size of bytes to read 
 * 
 * Reads @param size bytes from the file opened as @param fd into 
 * @param buffer. Returns the number of bytes actually read, or -1 if the
 * file could not be read. Fd 0 reads from tbe keyobard using input_getc()
 */
int			//8
read(int fd, void* buffer, unsigned size)
{
  //printf("fd: %d, p: %p,size: %u\n", fd, buffer, size);
  unsigned count;
  unsigned u_buffer;
  unsigned i;

  struct vm_entry* vme;

  u_buffer = (unsigned) buffer;
  i = u_buffer;

  for (; i < u_buffer + size; i = i + PGSIZE) {
    vme = find_vme((void*) i);
    vme->is_pinned = true;
    if (vme->is_loaded_to_memory == false)
      page_fault_handler(vme);
  }

	lock_acquire(&filesys_lock);

  count = size;
	if (fd == 0)
	{
    while (count != 0) {
      *((char * )buffer) = input_getc();
      buffer++;
      count--;
    }
		lock_release(&filesys_lock);
		return size;
	}
	else if (fd > 2) {
		struct file* f = get_file(fd);
		if (f == NULL) { 
      //unpin 
      i = u_buffer;
      for (; i < u_buffer + size; i = i + PGSIZE) {
        vme = find_vme((void*) i);
        vme->is_pinned = false;
      }
			lock_release(&filesys_lock);
			return -1; 
		}
		int ans = file_read(f, buffer, size);
		lock_release(&filesys_lock);

		return ans;
	}
  //unpin string 
  i = u_buffer;
  for (; i < u_buffer + size; i = i + PGSIZE) {
    vme = find_vme((void*) i);
    vme->is_pinned = false;
  }
	lock_release(&filesys_lock);

	return -1;
}

/**
 * @param fd      Fild Descriptor
 * @param buffer  File location
 * @param size    Size to write to file
 * @return Bytes actually written in unsigned. 
 * 
 * Writes @param size bytes from @param buffer to the open file @param fd 
 * @return bytes actually written in unsigned int. The bytes actually written 
 * may be smaller than @param size. If @param fd is 1, writes to console 
 * (stdout).  
 * 
 * Writing past EOF is not an error; rather, it should extend the file. 
 * This functionality will be implemented in PROJECT 4  
 */
int			//9
write(int fd, const void* buffer, unsigned size)
{
	//check_add_valid(buffer);
  //printf("fd: %d, buffer: %p, size: %d", fd, buffer, size);

  unsigned u_buffer;
  unsigned i;

  struct vm_entry* vme;

  u_buffer = (unsigned) buffer;
  i = u_buffer;
  for (; i < u_buffer + size; i = i + PGSIZE) {
    vme = find_vme((void*) i);
    vme->is_pinned = true;
    if (vme->is_loaded_to_memory == false)
      page_fault_handler(vme);
  }

	lock_acquire(&filesys_lock);

	if (fd == 1)
	{
		putbuf(buffer, size);
  	i = u_buffer;
    for (; i < u_buffer + size; i = i + PGSIZE) {
      vme = find_vme((void*) i);
      vme->is_pinned = false;
    }
		lock_release(&filesys_lock);
		return size;
	}
	else if (fd > 2){
		struct file* f = get_file(fd);
		if (f == NULL) { 
			lock_release(&filesys_lock);
			return -1; 
		}
		int ans = file_write(f, buffer, size);
		i = u_buffer;
    for (; i < u_buffer + size; i = i + PGSIZE) {
      vme = find_vme((void*) i);
      vme->is_pinned = false;
    }
		lock_release(&filesys_lock);
		return ans;
	}
	lock_release(&filesys_lock);
	return -1;
}

/**
 * @param fd file descriptor 
 * @param position position to change 
 * 
 * Chages the next byte to be read or written in open file @param fd to 
 * @param position, expressed in bytes from the beginning of the file. 
 * Thus, a @param position of 0 is the file's start 
 * 
 * A seek past the current EOF is not an error; a later read should obtain 
 * 0 bytes. A later write should extend the file, filling any unwritten gaps 
 * with zeros. 
 */ 
void		//10
seek(int fd, unsigned position)
{
	struct file* f = get_file(fd);
	if (f == NULL) exit(-1);
	file_seek(f, position);
}

/**
 * @param fd file descriptor
 * 
 * Returns the positif the next byte to be read or written in open file
 * @param fd, expressed in bytes from the beginning of the file. 
 */ 
unsigned	//11
tell(int fd)
{
	struct file* f = get_file(fd);
	if (f == NULL) return -1;
	return file_tell(f);
}

/**
 * @param fd file descriptor
 * 
 * Closes the file descriptor @param fd. Exiting / terminating a process 
 * implicitly closes all its open file descriptors, as if calling this 
 * funciton for each one. 
 */ 
void		//12
close(int fd)
{
	struct file* f = get_file(fd);
	if (f == NULL) exit(-1);
	close_file(fd);
}

/**
 * @param fd    file descriptor to map to @param addr
 * @param addr  page-aligned address to start mapping 
 * @returns     map_id if returned mmap() was successful, or error code(-1)
 * Maps @param fd to virtual address @param addr. 
 */ 
mapid_t 
mmap(int fd, void* addr) 
{
  int mmap_id;
  int file_length;
  int offset;
  struct file* file_pt_of_fd;
  struct file* new_file;
  struct mmap_file* mmap_file;
  struct vm_entry* vm_entry;

  //mmap fails if file size is 0, @param addr is not page aligned,
  //address is already in use, or addr is STDIN / STDOUT
  file_length = filesize(fd);
	if ((uint32_t)addr < 0x8048000 || (uint32_t)addr >= 0xc0000000)
    return -1;
  if (file_length== 0)
    return -1;
  if (find_vme(addr) != NULL)
    return -1;
  if (((unsigned int)addr % PGSIZE) != 0)
    return -1;
  if (fd == 0 || fd == 1) 
    return -1;
  
  file_pt_of_fd = get_file(fd);
  new_file = file_reopen(file_pt_of_fd);
  offset = 0;

  mmap_id = thread_current()->mmap_id_max;
  thread_current()->mmap_id_max++;

  mmap_file = (struct mmap_file*) malloc (sizeof (struct mmap_file));

  if (mmap_file == NULL)
    return -1;
  
  mmap_file->mapping_id = mmap_id;
  mmap_file->file = new_file;
  list_init(&mmap_file->vme_list);

  list_push_back(&thread_current()->mmap_list, &mmap_file->elem);
  
  while (file_length > 0) {
    if (find_vme(addr) != NULL)
      return -1;
    
    vm_entry = (struct vm_entry *)calloc(sizeof (struct vm_entry), 1);
    vm_entry->file_type = VM_FILE;
    vm_entry->file = new_file;
    vm_entry->offset = offset;
    vm_entry->write_permission = true;
    if (file_length >= PGSIZE) {
      vm_entry->read_bytes = PGSIZE;
    } else {
      vm_entry->read_bytes = file_length;
    }
    vm_entry->zero_bytes = PGSIZE - vm_entry->read_bytes;
    vm_entry->is_loaded_to_memory = false;
    vm_entry->va = addr;  
    vm_entry->is_pinned = true;

    list_push_back (&mmap_file->vme_list, &vm_entry->mmap_elem);
    insert_vme (&thread_current ()->vm, vm_entry);

    addr += PGSIZE;
    file_length -= PGSIZE;
    offset += PGSIZE;
  }

  return mmap_id;
}

/**
 * @param mapid id of mapped mm_file 
 * Unmap that mapped file denoted by @param mapid 
 */ 
void 
munmap(mapid_t mapid) 
{
  struct mmap_file* mmap_file;
  struct list_elem* e;
  struct vm_entry* vme;
  
  bool vme_is_loaded ;
  bool dirty_bit;

  mmap_file = get_mmap_file(mapid);
  if (mmap_file == NULL)
    exit(-1);

  e = list_begin(&mmap_file->vme_list);

  for (; e != list_end(&mmap_file->vme_list);
       ) 
    {
      vme = list_entry(e, struct vm_entry, mmap_elem);
      vme_is_loaded = vme->is_loaded_to_memory;
      dirty_bit = pagedir_is_dirty(thread_current()->pagedir, vme->va);
      if (vme_is_loaded && dirty_bit) {
        file_write_at (vme->file, vme->va, vme->read_bytes, vme->offset);
        free_physical_page_frame(vme->va);
      }
            
      vme->is_loaded_to_memory = false;
      vme->is_pinned = false;
      e = list_remove(e);
      delete_vme(&thread_current()->vm, vme);
    }
  list_remove(&mmap_file->elem);
  free(mmap_file);  
}


/** 
 * @param file pointer to struct file
 * @return file descritptor for file 
 * 
 * Creates a new file descriptor in the current thread of @param file by 
 * allocating space in the file descriptor table. 
 * Returns the file descriptor in the file descriptor table of the current
 * thread. 
 */ 
int 
new_file(struct file* file)
{
	if (file == NULL) return -1;

	struct thread* t = thread_current();
	int new_fd_num = t->fd_max;
	t->fd_table[new_fd_num] = file;
	t->fd_max = new_fd_num + 1;
	return new_fd_num;
}

/**
 * @param fd file descriptor 
 * @return file pointer 
 * 
 * Gets the file denoted by @param fd in the file descriptor table of the 
 * current thread.  
 */ 
struct file*
get_file(int fd)
{
	struct thread* t = thread_current();
	if (t->fd_table[fd] == NULL)
		return NULL;
	else
		return t->fd_table[fd];
}

/**
 * @param fd file descriptor 
 * 
 * Closes @param fd of the current thread. Remove file descritptor from 
 * file descriptor table. 
 */ 
void 
close_file(int fd)
{
	struct file* f = get_file(fd);
	if (f == NULL) return;

	file_close(f);
	thread_current()->fd_table[fd] = NULL;
}

/**
 * @param     mmap_id
 * @returns   pointer to the mmap_file
 * Gets the mmap_file denoted by @mmap_id in the mmap_list of the 
 * current thread.
 */ 
struct mmap_file* 
get_mmap_file(int mmap_id) 
{
  struct thread* t;
  struct list_elem* e;
  struct mmap_file* m;

  t = thread_current();
  e = list_begin(&thread_current()->mmap_list);

  for (; e != list_end(&thread_current()->mmap_list); 
       e = list_next(e)) 
  {
    m = list_entry(e, struct mmap_file, elem);
    if (m->mapping_id == mmap_id)
      return m;
  }
  return NULL;
}