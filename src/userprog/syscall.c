#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
static void copy_in (void *dst_, const void *usrc_, size_t size);
static inline bool get_user (uint8_t *dst, const uint8_t *usrc);
static bool verify_user (const void *uadder);
void sys_exit(int status);
pid_t sys_exec( const char * cmd_line);
int sys_wait ( pid_t pid);
bool sys_create( const char* file, unsigned initial_size);
bool sys_remove(const char * file);
int sys_open(const char* file);
int sys_filesize(int fd);
int sys_read(int fd, const void* buffer, unsigned size);
int sys_write(int fd, const void* buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);

struct file_descriptor
{
  struct list_elem fd_elem;
  struct file *file;
  int fd_num;
};

struct file_descriptor * find_fd (int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  unsigned callNum;
  int args[3];
  int numOfArgs;

  copy_in (&callNum, f->esp, sizeof callNum);

  numOfArgs = 1;		//JUST FOR TESTING HAVE TO CHANGE
  if (callNum == SYS_HALT)
    numOfArgs = 0;
  else if (callNum == SYS_CREATE || callNum == SYS_SEEK)
    numOfArgs = 2;
  else if (callNum == SYS_READ || callNum == SYS_WRITE)
    numOfArgs = 3;

  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);

  printf ("System call %i with %i args!\n", callNum, numOfArgs);

  switch(callNum)
  {
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      sys_exit(args[0]);
      thread_exit();
    case SYS_EXEC:
      f->eax = sys_exec(args[0]);
      break;
    case SYS_WAIT:
      f->eax = sys_wait(args[0]);
      break;
    case SYS_CREATE:
      f->eax = sys_create(args[0], args[1]);
      break;
    case SYS_REMOVE:
      f->eax = sys_remove(args[0]);
      break;
    case SYS_OPEN:
      f->eax = sys_open(args[0]);
      break;
    case SYS_FILESIZE:
      f->eax = sys_filesize(args[0]);
      break;
    case SYS_READ:
      f->eax = sys_read(args[0], args[1], args[2]);
      break;
    case SYS_WRITE:
      f->eax = sys_write(args[0], args[1], args[2]);
      break;
    case SYS_SEEK:
      sys_seek(args[0], args[1]);
      break;
    case SYS_TELL:
      f->eax = sys_tell(args[0]);
      break;
    case SYS_CLOSE:
      sys_close(args[0]);
      break;
    default:
      thread_exit();
  }

  //printf ("system call!\n");
  //thread_exit ();
}

void
sys_exit(int status)
{
  thread_current()->wait_stat->exit_status = status;
  thread_exit();
  NOT_REACHED();
}

pid_t
sys_exec(const char*cmd_line)
{
  return process_execute(cmd_line);
}

int
sys_wait (pid_t pid)
{
  return process_wait(pid);
}

bool
sys_create (const char *file, unsigned initial_size)
{
  //implement later
  return false;
}

bool
sys_remove (const char *file)
{
  //implement later
  return false;
}

int
sys_open (const char *file)
{
  //implement
  return false;
}

int
sys_filesize (int fd)
{
  //implement later
  return -1;
}

int
sys_read (int fd, const void *buffer, unsigned size)
{
  //implement later
  return -1;
}

int
sys_write (int fd, const void *buffer, unsigned size)
{
  //implement later
  return -1;
}

void
sys_seek (int fd, unsigned position)
{
  struct file *file = find_fd(fd)->file;
  file_seek(file, position);
  return;
}

unsigned
sys_tell (int fd)
{
  struct file *file = find_fd(fd)->file;
  return file_tell(file);
}

void
sys_close (int fd)
{
  //implement later
  return;
}

static void 
copy_in (void *dst_, const void *usrc_, size_t size)
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;

  for (; size > 0; size--, dst++, usrc++)
  {
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user(dst, usrc))
      thread_exit();
  }
}

static inline bool 
get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
    : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}

static bool
verify_user (const void *uaddr)
{
  return (uaddr < PHYS_BASE && pagedir_get_page(thread_current()->pagedir, uaddr) != NULL);
}

struct file_descriptor *
find_fd (int fd)
{
  struct list_elem * e = list_begin(&thread_current()->fd_list);
  while (e != list_end(&thread_current()->fd_list))
  {
    struct file_descriptor *f = list_entry(e, struct file_descriptor, fd_elem);
    if (f->fd_num == fd)
    {
      return f;
    }
  }
  return NULL;
}
