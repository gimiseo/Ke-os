#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

//true, flase define
#define TRUE 1
#define FALSE 0

void syscall_entry (void);
void syscall_handler (struct intr_frame *);


// int write (int fd, const void *buffer, unsigned size)
// {
// 	char f_buffer[size+1];
// 	strlcpy(f_buffer, (char *)buffer, size);
// 	putbuf(f_buffer, size);
// 	return size;
// }

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

static bool
user_memory_access (const void *addr){
	if (addr == NULL || addr > KERN_BASE || 
		pml4_get_page(thread_current()->pml4, addr) == NULL)
		return FALSE;
	return TRUE;
}

static bool
create (const char *file, unsigned initial_size) {
	if (user_memory_access(file) != TRUE)
	{
		thread_current()->exit_num = -1;
		thread_exit ();
		return FALSE;
	}
	if(filesys_create(file, initial_size))
		return TRUE;
	else
		return FALSE;
}


/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int syscall_num = f->R.rax;

	int fd;
	void *buf;
	size_t size;
	switch(syscall_num){
		case SYS_HALT:
			power_off();
			break;
		case SYS_EXIT:
			f->R.rax = f->R.rdi;
			thread_current()->exit_num = (int)f->R.rdi;
			thread_exit ();
			break;
		case SYS_WRITE:
			// f->R.rax = write(f->R.rdi,(void *)f->R.rsi, f->R.rdx);
			buf = f->R.rsi;
			size = f->R.rdx;
			putbuf(buf,size);
			f->R.rax = size;
			break;
		case SYS_CREATE:
			if(create((char *)f->R.rdi, (unsigned)f->R.rsi))
				f->R.rax = TRUE;
			else
				f->R.rax = FALSE;
			break;
	}
}
