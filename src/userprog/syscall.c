#include "syscall.h"
#include "pagedir.h"
#include <user/syscall.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "process.h"

#define ERROR -1
#define MAX_ARGUMENTS 3

struct lock file_lock;

static void syscall_handler (struct intr_frame *);

// syscall worker functions
void halt(void);
void exit(int);
pid_t exec(const char* cmd_line);
bool create(const char* file, unsigned initial_size);
bool remove(const char* file);
int open(const char* file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned length);
int write(int fd, const void *buffer, unsigned length);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

// helper functions
void retrieve_args_from_intr_frame(struct intr_frame* frame, int* args, int num_args);
int translate_to_kernel_pointer(const void* pointer);
void validate_pointer(const void*);
void validate_buffer(void* buffer, unsigned size);
int syscall_wait(pid_t pid);

void syscall_init(void)
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
  int args[MAX_ARGUMENTS];
  validate_pointer(f->esp);

  switch(* (int*) f->esp)
  {
    case SYS_HALT:
    {
      halt();
      break;
    }
    case SYS_EXIT:
    {
      retrieve_args_from_intr_frame(f, &args[0], 1);
      exit(args[0]);
      break;
    }
    case SYS_EXEC:
    {
      retrieve_args_from_intr_frame(f, &args[0], 1);
      args[0] = translate_to_kernel_pointer((const void*) args[0]);
      f->eax = exec((const char*) args[0]);
      break;
    }
    case SYS_WAIT:
    {
      retrieve_args_from_intr_frame(f, &args[0], 1);
      f->eax = syscall_wait(args[0]);
      break;
    }
    case SYS_CREATE:
    {
      retrieve_args_from_intr_frame(f, &args[0], 2);
      args[0] = translate_to_kernel_pointer((const void*) args[0]);
      f->eax = create((const char*) args[0], (unsigned) args[1]);
      break;
    }
    case SYS_REMOVE:
    {
      retrieve_args_from_intr_frame(f, &args[0], 1);
      args[0] = translate_to_kernel_pointer((const void*) args[0]);
      f->eax = remove((const char*) args[0]);
      break;
    }
    case SYS_OPEN:
    {
      retrieve_args_from_intr_frame(f, &args[0], 1);
      args[0] = translate_to_kernel_pointer((const void*) args[0]);
      f->eax = open((const char*) args[0]);
      break;
    }
    case SYS_FILESIZE:
    {
      retrieve_args_from_intr_frame(f, &args[0], 1);
      f->eax = filesize(args[0]);
      break;
    }
    case SYS_READ:
    {
      retrieve_args_from_intr_frame(f, &args[0], 3);
      validate_buffer((void*) args[1], (unsigned) args[2]);
      args[1] = translate_to_kernel_pointer((const void*) args[1]);
      f->eax = read(args[0], (void*) args[1], (unsigned) args[2]);
      break;
    }
    case SYS_WRITE:
    {
      retrieve_args_from_intr_frame(f, &args[0], 3);
      validate_buffer((void*) args[1], (unsigned) args[2]);
      args[1] = translate_to_kernel_pointer((const void*) args[1]);
      f->eax = write(args[0], (void*) args[1], (unsigned) args[2]);
      break;
    }
    case SYS_SEEK:
    {
      retrieve_args_from_intr_frame(f, &args[0], 2);
      seek(args[0], (unsigned) args[1]);
      break;
    }
    case SYS_TELL:
    {
      retrieve_args_from_intr_frame(f, &args[0], 1);
      f->eax = tell(args[0]);
      break;
    }
    case SYS_CLOSE:
    {
      retrieve_args_from_intr_frame(f, &args[0], 1);
      close(args[0]);
      break;
    }
    default:
    {
      // now you fucked up.
      break;
    }
  }
}

void halt(void)
{
  shutdown_power_off();
}

void exit(int status)
{
  struct thread* current = thread_current();
  printf("%s: exit(%d)\n", current->name, status);
  thread_exit();
}

pid_t exec(const char* cmd_line)
{
  pid_t new_process_pid = process_execute(cmd_line);
  struct child_process* child = get_child_process(new_process_pid);
  ASSERT(child);

  while(child->load_status == NOT_LOADED)
    barrier();

  if(child->load_status == LOAD_FAILED)
    return ERROR;

  return new_process_pid;
}

bool create(const char* file, unsigned initial_size)
{
  lock_acquire(&file_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return success;
}

bool remove(const char* file)
{
  lock_acquire(&file_lock);
  bool success = filesys_remove(file);
  lock_release(&file_lock);
  return success;
}

int open(const char* file)
{
  int fd;

  lock_acquire(&file_lock);
  struct file* f = filesys_open(file);
  
  fd = f == NULL
            ? -1 
            : add_file(f);

  lock_release(&file_lock);
  return fd;
}

int filesize(int fd)
{
  int size;

  lock_acquire(&file_lock);

  struct file* f = get_file(fd);
  size = f == NULL 
              ? -1 
              : file_length(f);

  lock_release(&file_lock);

  return size;
}

int read(int fd, void *buffer, unsigned length)
{
  if(fd == STDIN_FILENO)
  {
    unsigned i;
    uint8_t* cast_buffer = (uint8_t*) buffer;

    for(i = 0; i < length; i++)
    {
      cast_buffer[i] = input_getc();
    }

    return length;
  }

  int bytes_read;
  lock_acquire(&file_lock);

  struct file* f = get_file(fd);
  bytes_read = f == NULL 
                    ? -1 
                    : file_read(f, buffer, length);

  lock_release(&file_lock);
  return bytes_read;
}

int write(int fd, const void *buffer, unsigned length)
{
  if(fd == STDOUT_FILENO)
  {
    putbuf(buffer, length);
    return length;
  }

  int bytes_written;

  lock_acquire(&file_lock);

  struct file* f = get_file(fd);

  bytes_written = f == NULL
                       ? 0
                       : file_write(f, buffer, length);

  lock_release(&file_lock);

  return bytes_written;
}

void seek(int fd, unsigned position)
{
  lock_acquire(&file_lock);

  struct file* f = get_file(fd);

  if(f != NULL)
    file_seek(f, position);

  lock_release(&file_lock);
}

unsigned tell(int fd)
{
  unsigned offset;

  lock_acquire(&file_lock);

  struct file* f = get_file(fd);
  offset = f == NULL 
                ? -1 
                : file_tell(f);

  lock_release(&file_lock);

  return offset;
}

void close(int fd)
{
  lock_acquire(&file_lock);
  close_file(fd);
  lock_release(&file_lock);
}

void retrieve_args_from_intr_frame(struct intr_frame* frame, 
                                   int* args, 
                                   int num_args)
{
  int i;
  int* arg_pointer;

  for(i = 0; i < num_args; i++)
  {
    arg_pointer = (int*) frame->esp + i + 1;
    validate_pointer(arg_pointer);
    args[i] = *arg_pointer;
  }
}

int translate_to_kernel_pointer(const void* pointer)
{
  validate_pointer(pointer);

  void* kernel_pointer = pagedir_get_page(thread_current()->pagedir, pointer);
  if(!kernel_pointer)
    exit(ERROR);

  return (int) kernel_pointer;
}

void validate_pointer(const void* pointer)
{
  if(!is_user_vaddr(pointer))
    exit(ERROR);
}

void validate_buffer(void* buffer, unsigned size)
{
  unsigned i;
  char* cast_buffer = (char*) buffer;
  
  for(i = 0; i < size; i++, cast_buffer++)
  {
    validate_pointer((const void*) cast_buffer);
  }
}

int
syscall_wait (pid_t pid)
{
  return process_wait(pid);
}

int add_file(struct file* f)
{
  struct thread* cur = thread_current();

  struct process_file* pf = malloc(sizeof(struct process_file));
  pf->file = f;
  pf->fd = cur->fd;

  cur->fd++;

  list_push_back(&cur->file_list, &pf->elem);

  return pf->fd;
}

struct file* get_file(int fd)
{
  struct thread* cur = thread_current();
  struct list_elem* e;

  for(e = list_begin(&cur->file_list); 
      e != list_end(&cur->file_list);
      e = list_next(e))
  {
    struct process_file* pf = list_entry(e, struct process_file, elem);

    if(fd == pf->fd)
    {
      return pf->file;
    }
  }

  return NULL;
}

void close_file(int fd)
{
  struct thread* cur = thread_current();  
  struct list_elem* e;

  for(e = list_begin(&cur->file_list);
      e != list_end(&cur->file_list);
      e = list_next(e))
  {
    struct process_file* pf = list_entry(e, struct process_file, elem);    

    if(pf->fd == fd)
    {
      file_close(pf->file);
      list_remove(&pf->elem);
      free(pf);
      return;
    }
  }
}

void close_all_files(void)
{
  struct thread* cur = thread_current();
  struct list_elem* next;
  struct list_elem* e;

  for(e = list_begin(&cur->file_list);
      e != list_begin(&cur->file_list);)
  {
    next = list_next(e);
    
    struct process_file* pf = list_entry(e, struct process_file, elem);
    file_close(pf->file);
    list_remove(&pf->elem);
    free(pf);

    e = next;
  }
}