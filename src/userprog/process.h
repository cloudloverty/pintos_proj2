#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h" 
#include "vm/page.h"

#define USER_STACK_GROW_LIMIT 32;
#define USER_STACK_BOTTOM 0xc0000000 - 0x800000;

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct thread* get_child_process(int);
void remove_child_process(struct thread*);

bool page_fault_handler(struct vm_entry*);

bool grow_stack(void*);

#endif /* userprog/process.h */
