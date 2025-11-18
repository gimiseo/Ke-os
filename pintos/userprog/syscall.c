#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "lib/kernel/stdio.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
/* project2 */
void validate_addr (void *addr);
void validate_fn (char *file_name);

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

/* project2 */
void
validate_addr (void *addr) {
	// 유저 영역인지, pagetable에 매핑되어 있는지 
	bool is_user = is_user_vaddr(addr);
	uint64_t *pm = thread_current()->pml4;
	bool is_mapped_pte = pml4_get_page(pm, addr);
	if(!is_user || !is_mapped_pte) {
		struct thread *curr = thread_current();
		curr->exit_num = -1;
		thread_exit();
	}
}

void
validate_fn (char *file_name) {
	struct thread *curr = thread_current();
	if(file_name == NULL || 
		file_name[0] == '\0' || 
		strcmp(file_name,  "no-such-file") == 0) 
		{
		curr->exit_num = -1;
		thread_exit();
	}
}


/* The main system call interface */
void syscall_handler (struct intr_frame *f UNUSED) {
	uint64_t rax = f->R.rax;

	switch(rax) {
		case SYS_WRITE : 
			int fd = f->R.rdi;
			char *buf = f->R.rsi;
			unsigned size = f->R.rdx;

			/* TD : 2 need to validate fd, buf */ 
			struct thread *cur = thread_current();

			if(fd == 1){
				putbuf(buf, size);
				f->R.rax = size;
			}else{
				// 여기는 파일 open 구현하고...?
				// file_write(fd, buf, size);
			}	
			break;
			
		case SYS_WAIT :
			tid_t tid = thread_current()->tid;
			process_wait(tid);
			break;
			
		case SYS_EXEC : {
			/* TD : need to validate file_name */
			char *file_name = f->R.rdi;
			process_exec(file_name);
			break;
		}
			
		case SYS_CREATE : {
			// 새로운 파일을 생성한다.
			char *file_name = f->R.rdi;
			validate_addr(file_name);
			validate_fn(file_name);

			unsigned initial_size = f->R.rsi;
			bool suc = filesys_create(file_name, initial_size);
			f->R.rax = suc;
			break;
		}

		case SYS_EXIT : {
			struct thread *curr = thread_current();
			curr->exit_num = f->R.rdi;
			// printf ("%s: exit(%d)\n", curr->name, curr->exit_num);
			thread_exit();
			break;
		}

		case SYS_OPEN : {
			// 파일 이름에 대한 검증
			char *file_name = f->R.rdi;
			struct thread *curr = thread_current();
			bool is_user = is_user_vaddr(file_name);
			uint64_t *pm = thread_current()->pml4;
			bool is_mapped_pte = pml4_get_page(pm, file_name);

			// validate mapping, fileName
			// 개 스렉히 코드... 리펙토링 필요.....
			if(!is_user || !is_mapped_pte){
				curr->exit_num = -1;
				// printf ("%s: exit(%d)\n", curr->name, curr->exit_num);
				thread_exit();
				break;
			}
			if(file_name == NULL || 
			file_name[0] == '\0' || 
			strcmp(file_name,  "no-such-file") == 0) {
				f->R.rax = -1;
				break;
			}
			// file open
			struct file *file = filesys_open(file_name);
			if(file == NULL) {
				curr->exit_num = -1;
				thread_exit();
			}
			// 파일 디스크럽터 설정
			int fd_num = curr->fd_next;
			curr->fd_table[fd_num] = file;
			f->R.rax = fd_num;
			curr->fd_next += 1;
			break;
		}

		case SYS_CLOSE : {
			int fd = f->R.rdi; //요청 fd 가져오기
			struct thread *curr = thread_current(); 
			struct file *file = curr->fd_table[fd]; //fd에 해당하는 file가져오기
			// validate fd & file
			if(fd < 0 || fd > 32){
				curr->exit_num = -1;
				thread_exit();
			}
			if(file == NULL) {
				curr->exit_num = -1;
				thread_exit();
			}

			curr->fd_table[fd] = NULL;
			file_close(file);
			break;
		}
	}	
}