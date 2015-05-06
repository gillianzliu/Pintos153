#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //FIXME CHECK TO SEE IF POINTER IS VALID
  //THEN GET SYSCALL NUMBER 
  unsigned callNum;
  int args[3];
  int numOfArgs;

  copy_in (&call_nr, f->esp, sizeof callNum);

  //numOfArgs = number of arguments the systemcall uses
  //
  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);

  case SYS_WRITE:
  {
    get_arg(f , &arg[0], 3);
    check_valid_buffer((void *) arg[1], (unsigned) arg[2]);
    arg[1] = user_to_kernel_ptr((const void *) arg[1]);
    f->eax = write(arg[0], (const void *) arg[1], (unsigned) arg[2]);
    break;
  }
  //printf ("system call!\n");
  //thread_exit ();
  //
  f->eax = desired_sys_call_fun(args[0], args[1], args[2]);
}

static void
copy_in (void *dst_, const void *usrc_, size_t size)
{
  uint8_t *dst = dst_;
  const unit8_t *usrc = usrc_;

  for (; size > 0; size--, dst++, usrc++)
  {
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user(dst, usrc))
      thread_exit();
  }
}

static char*
copy_in_string(const char *us)
{
  char *ks;
  size_t length;

  ks = palloc_get_page(0);
  if (ks == NULL)
  {
    thread_exit();
  }

  for (length = 0; length < PGSIZE; length++)
  {
    if (us >= (char *) PHYS_BASE || !get_user(ks + length, us++))
    {
      palloc_free_page(ks);
      thread_exit();
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
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
      : "=m" (*dst), "=&a" (eax)  : "m" (*usrc));
  return eax != 0;
}

static bool
verify_user (const void* uaddr)
{
  return (uaddr < PHYS_BASE && pagedir_get_page (thread_current()->pagedir, uaddr) != NULL);
}
