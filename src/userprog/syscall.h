#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdio.h>
#include "lib/user/syscall.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

void syscall_init (void);

void set_arg(void*, uint32_t*, int);

void exit(int);
void halt(void);
pid_t exec(const char*);
int wait(pid_t pid);
bool create(const char*, unsigned);
bool remove(const char*);
int open(const char*);
int filesize(int);
int read(int, void*, unsigned);
int write(int, const void*, unsigned);
void seek(int, unsigned);
unsigned tell(int);
void close(int);

int new_file(struct file*);
struct file* get_file(int);
void close_file(int);

struct lock filesys_lock;

#endif /* userprog/syscall.h */
