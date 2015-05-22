#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "lib/string.h"

static void syscall_handler (struct intr_frame *);
static void copy_in (void *dst_, const void *usrc_, size_t size);
static char* copy_in_string (const char *us);
static inline bool get_user (uint8_t *dst, const uint8_t *usrc);
static bool verify_user (const void *uadder);
static bool verify_buffer(void *buffer, unsigned size);

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

struct file_descriptor * find_fd (int fd);
bool cmp_fd(const struct list_elem *a, const struct list_elem *b, void* aux);

struct semaphore file_access;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  sema_init(&file_access, 1);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if (!verify_user(f->esp))
    sys_exit(-1);

  unsigned callNum;
  int args[3];
  int numOfArgs;

  copy_in (&callNum, f->esp, sizeof callNum);

  //printf ("System call %i\n", callNum);// with %i args!\n", callNum, numOfArgs);

  numOfArgs = 1;		//JUST FOR TESTING HAVE TO CHANGE
  if (callNum == SYS_HALT)
    numOfArgs = 0;
  else if (callNum == SYS_CREATE || callNum == SYS_SEEK)
    numOfArgs = 2;
  else if (callNum == SYS_READ || callNum == SYS_WRITE)
  {
    numOfArgs = 3;
  }

  int i = 1;
  for (; i <= numOfArgs; ++i)
  {
    if (!verify_user((int *)f->esp + i))
      sys_exit(-1);
  }

  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);

  switch(callNum)
  {
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      sys_exit(args[0]);
      break;
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
  printf("%s: exit(%i)\n", thread_current()->name, status);
  thread_current()->wait_stat->exit_status = status;
  sema_up(&thread_current()->wait_stat->make_wait);
  thread_exit();     //possibly needs to be process_exit
  NOT_REACHED();
}

pid_t
sys_exec(const char *cmd_line)
{
  if (cmd_line == NULL || !verify_user(cmd_line))
    sys_exit(-1);

  char* kernel_cmd_line = copy_in_string(cmd_line);

  sema_down(&file_access);
  pid_t pid = process_execute(kernel_cmd_line);
  sema_up(&file_access);

  return pid;
}

int
sys_wait (pid_t pid)
{
  return process_wait(pid);
}

bool
sys_create (const char *file, unsigned initial_size)
{
  if (file == NULL || !verify_user(file))
    sys_exit(-1);

  bool pass;

  sema_down(&file_access);
  pass = filesys_create(file, initial_size);
  sema_up(&file_access);

  return pass;
}

bool
sys_remove (const char *file)
{
  if (!verify_user(file))
    sys_exit(-1);

  sema_down(&file_access);
  bool pass = filesys_remove(file);
  sema_up(&file_access);

  return pass;
}

int
sys_open (const char *file)
{
  if (file == NULL || !verify_user(file))
    sys_exit(-1);

  int fd_slot = 2;

  if (!list_empty(&thread_current()->fds))
  {
    struct list_elem *e = list_begin(&thread_current()->fds);
    for (; e != list_end(&thread_current()->fds); e = list_next(e))
    {
      struct file_descriptor *temp = list_entry(e, 
           struct file_descriptor, fd_elem); 
      if (temp->fd_num < fd_slot)
      {
        continue;
      }
      else if (temp->fd_num == fd_slot)
      {
        fd_slot++;
      }
      else
        break;
    }
  }

  sema_down(&file_access);
  struct file *open_file = filesys_open(file);
  sema_up(&file_access);

  if (open_file == NULL)
    return -1;

  struct file_descriptor *new = malloc(sizeof *new);
  new->fd_num = fd_slot;
  new->file = open_file;

  list_insert_ordered(&thread_current()->fds, &new->fd_elem, cmp_fd, NULL);
   
  return new->fd_num;
}

int
sys_filesize (int fd)
{
  struct file_descriptor *fd_size = find_fd(fd);
  
  sema_up(&file_access);
  int size = file_length(fd_size->file);
  sema_down(&file_access);

  return size;
}

int
sys_read (int fd, const void *buffer, unsigned size)
{
  if (!verify_buffer(buffer, size))
    sys_exit(-1);

  int read_size = 0;

  if (fd == STDIN_FILENO)
  {
    strlcat(buffer, input_getc(), 1);
    read_size = 1;
  }
  else if (fd == STDOUT_FILENO)
  {
    sys_exit(-1);
  }
  else
  {
    struct file_descriptor *fd_read = find_fd(fd);
    if (fd_read == NULL)
      return -1;
    
    sema_down(&file_access);
    read_size = file_read(fd_read->file, buffer, size);
    sema_up(&file_access);
  }

  return read_size;
}

int
sys_write (int fd, const void *buffer, unsigned size)
{
  int write_size = 0;
  
  if (!verify_user(buffer) || !verify_buffer(buffer, size))
    sys_exit(-1);

  if (fd == STDOUT_FILENO)
  {
    putbuf(buffer, size);
    return size;
  }
  else if (fd == STDIN_FILENO)
  {
    sys_exit(-1);
  }

  struct file_descriptor *fd_write = find_fd(fd);
  if (fd_write == NULL)
    return -1;

  sema_down(&file_access);
  write_size = file_write(fd_write->file, buffer, size);
  sema_up(&file_access);

  return write_size;
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
  struct file_descriptor *fd_close = find_fd(fd);
  if (fd_close == NULL)
    return;

  sema_down(&file_access);
  file_close(fd_close->file);
  sema_up(&file_access);

  list_remove(&fd_close->fd_elem);

  free(fd_close);
}

static void 
copy_in (void *dst_, const void *usrc_, size_t size)
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;

  for (; size > 0; size--, dst++, usrc++)
  {
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user(dst, usrc))
      sys_exit(-1);
  }
}

static char* 
copy_in_string (const char *us)
{
  char *ks;
  size_t length;
  
  ks = palloc_get_page(0);
  if (ks == NULL)
    sys_exit(-1);

  for (length = 0; length < PGSIZE; length++)
  {
    if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++))
    {
      palloc_free_page(ks);
      sys_exit(-1);
    }
  
    if (ks[length] == '\0')
      return ks;
  }
  
  ks[PGSIZE - 1] = '\0';
  return ks;
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
  if (uaddr == NULL)
    return false;

  return (uaddr < PHYS_BASE && pagedir_get_page(thread_current()->pagedir, uaddr) != NULL);
}

struct file_descriptor *
find_fd (int fd)
{
  struct list_elem * e = list_begin(&thread_current()->fds);
  while (e != list_end(&thread_current()->fds))
  {
    struct file_descriptor *f = list_entry(e, struct file_descriptor, fd_elem);
    if (f->fd_num == fd)
    {
      return f;
    }
  }
  return NULL;
}

bool 
cmp_fd(const struct list_elem *a, const struct list_elem *b, void* aux)
{
  struct file_descriptor *p = list_entry(a, struct file_descriptor, fd_elem);
  struct file_descriptor *t = list_entry(b, struct file_descriptor, fd_elem);
 
  return p->fd_num < t->fd_num;
}

static bool
verify_buffer(void *buffer, unsigned size)
{
  int i = 0;
  for (; i < size; i++)
  {
    if (!verify_user(buffer + i))
      return false;
  }
  return true;
}
  
  
