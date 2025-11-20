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

static void
user_memory_access (const void *addr){
	if (addr == NULL || addr > KERN_BASE || 
		pml4_get_page(thread_current()->pml4, addr) == NULL) {
		thread_current()->exit_num = -1;
		thread_exit ();
	}
}

static bool
create (const char *file, unsigned initial_size) {
	user_memory_access(file);
	if (filesys_create(file, initial_size))
		return TRUE;
	else
		return FALSE;
}

static int
open (const char *file_name) {
	struct file *file = NULL;
	struct thread *curr = thread_current();
	int fd;
	user_memory_access(file_name);
	file = filesys_open (file_name);
	fd = curr->next_num;
	if (file == NULL || fd >= FILE_MAX)
		return -1;
	curr->file_descrs[fd] = file;
	curr->next_num++;
	return fd;
}

static void
close (int fd) {
	struct file *file = NULL;
	struct thread *curr = thread_current();
	if (fd < 0 || fd >= FILE_MAX) {
		thread_current()->exit_num = -1;
		thread_exit ();
	}
	file = curr->file_descrs[fd];
	if (file == NULL)
	{
		thread_current()->exit_num = -1;
		thread_exit ();
	}
	file_close(file);
	curr->file_descrs[fd] = NULL;
}

static int
read (int fd, void *buffer, unsigned size) {
	struct file *file = NULL;
	struct thread *curr = thread_current();
	user_memory_access(buffer);
	int read_byte;
	if (fd < 0 || fd >= FILE_MAX || fd == 1)
		return -1;
	// if (fd == 0) { 보류
	// 	input_getc();
	// }
	file = curr->file_descrs[fd];
	if (file == NULL)
	{
		thread_current()->exit_num = -1;
		thread_exit ();
	}
	read_byte = file_read (file, buffer, size);
	return read_byte;
}

static int
write (int fd, void *buffer, unsigned size) {
	struct file *file = NULL;
	struct thread *curr = thread_current();
	user_memory_access(buffer);
	int read_byte;
	if (fd < 0 || fd >= FILE_MAX || fd == 0)
		return -1;
	file = curr->file_descrs[fd];
	if (file == NULL)
	{
		thread_current()->exit_num = -1;
		thread_exit ();
	}
	read_byte = file_write (file, buffer, size);
	return read_byte;
}


static tid_t 
fork (const char *thread_name, struct intr_frame *f) {
	tid_t tid;
	user_memory_access(thread_name);
	return process_fork(thread_name, f);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	int syscall_num = f->R.rax;

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
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
			break;
		case SYS_CREATE:
			if(create((char *)f->R.rdi, (unsigned)f->R.rsi))
				f->R.rax = TRUE;
			else
				f->R.rax = FALSE;
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			int fd = f->R.rdi;
			if (fd < 2 || fd >= FILE_MAX || thread_current()->file_descrs[fd] == NULL){
				f->R.rax = -1;
			}
			else {
				f->R.rax = (uint64_t)file_length(thread_current()->file_descrs[fd]);
			}
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		case SYS_WRITE:
			if (f->R.rdi == 1)
			{
				putbuf(f->R.rsi,f->R.rdx);
				f->R.rax = size;
			}
			else {
				f->R.rax = write(f->R.rdi,f->R.rsi, f->R.rdx);
			}
			break;
		
	}
}
