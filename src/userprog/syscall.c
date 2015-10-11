#include "syscall.h"
#include "pagedir.h"
#include <user/syscall.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
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

// helper functions
void retrieve_args_from_intr_frame(struct intr_frame* frame, int* args, int num_args);
int translate_to_kernel_pointer(const void* pointer);
void validate_pointer(const void*);
int syscall_wait(pid_t pid);

void syscall_init(void)
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED) 
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
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_READ:
    case SYS_WRITE:
    case SYS_SEEK:
    case SYS_TELL:
    case SYS_CLOSE:
    {
      // TODO: implement these functionalities.
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

void retrieve_args_from_intr_frame(struct intr_frame* frame, int* args, int num_args)
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

int
syscall_wait (pid_t pid)
{
	return process_wait(pid);
}
