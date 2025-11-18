#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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

static void check_addr(char *addr) {
    struct thread *t = thread_current();
    if (addr == NULL || addr >= (char *)KERN_BASE || pml4_get_page(t->pml4, addr) == NULL) {
        t->exit_num = -1;
        thread_exit();
    }
}

/* Arguments order: %rdi, %rsi, %rdx, %r10, %r8, %r9 */
/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
    int fd, status;
    unsigned initial_size;
    uint8_t *buffer;
    char *file;
    unsigned size;

    struct thread *t = thread_current ();
	// TODO: Your implementation goes here.
    switch (f->R.rax) {
        case SYS_HALT:
            power_off();    
            break;

        case SYS_EXIT:
            status = f->R.rdi;

            t->exit_num = status;
            thread_exit ();
            break;

        case SYS_CREATE:
            file = (char *)f->R.rdi;
            initial_size = f->R.rsi;

            check_addr(file);
            f->R.rax = filesys_create(file, initial_size);
            break;

        case SYS_REMOVE:
            file = (char *)f->R.rdi;

            check_addr(file);
            f->R.rax = filesys_remove(file);
            break;

        case SYS_OPEN:
            file = (char *)f->R.rdi;

            check_addr(file);
            ASSERT(t->next_fd < MAX_FD);

            struct file *file_ptr = filesys_open(file);
            if (file_ptr == NULL) {
                f->R.rax = -1;
            } else {
                f->R.rax = t->next_fd;
                t->fd_table[t->next_fd++] = file_ptr;
            }
            break;
        
        case SYS_FILESIZE:
            fd = f->R.rdi;

            if (fd < 2 || fd >= MAX_FD || t->fd_table[fd] == NULL) {
                f->R.rax = -1;
            } else {
                f->R.rax = (uint64_t)file_length(t->fd_table[fd]);
            }
            break;

        case SYS_READ:
            fd = f->R.rdi;
            buffer = (uint8_t *)f->R.rsi;
            size = f->R.rdx;
            
            check_addr(buffer);
            if (fd == 0) {
                *buffer = input_getc();
                f->R.rax = 1;
            } else if (fd < 2 || fd >= MAX_FD || t->fd_table[fd] == NULL) {
                f->R.rax = -1;
            } else {
                off_t bytes_read = file_read(t->fd_table[fd], buffer, size);
                f->R.rax = (uint64_t)bytes_read;
            }
            break;

        case SYS_WRITE:
            fd = f->R.rdi;
            buffer = (char *)f->R.rsi;
            size = f->R.rdx;

            check_addr(buffer);
            putbuf(buffer, size);
            f->R.rax = size;
            break;
        
        case SYS_CLOSE:
            fd = f->R.rdi;
            
            if (fd < 2 || fd >= MAX_FD) {
                t->exit_num = -1;
                thread_exit();
            }

            if (t->fd_table[fd] != NULL) {
                file_close(t->fd_table[fd]);
                t->fd_table[fd] = NULL;
            }

            break;
    }
}
