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
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/init.h"

// true, flase define
#define TRUE 1
#define FALSE 0

void syscall_entry(void);
void syscall_handler(struct intr_frame*);

struct lock filesys_lock;

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

void syscall_init(void)
{
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
    lock_init(&filesys_lock);
}

/*fd 비교 함수*/
static bool cmp_fd_less(const struct list_elem* a, const struct list_elem* b, void* aux UNUSED)
{
    struct descriptor* fd_a = list_entry(a, struct descriptor, desc_elem);
    struct descriptor* fd_b = list_entry(b, struct descriptor, desc_elem);
    return fd_a->fd < fd_b->fd;
}

// open fd 결정해주는 함수
static int find_pos_fd_num(struct thread* curr)
{
    struct list_elem* iter;
    int prev_num = 1;
    // file_max 넘어가면 끝
    if (list_size(&(curr->descrs_t)) >= FILE_MAX)
        return -1;
    if (list_empty(&curr->descrs_t)) {
        return 2;
    }
    for (iter = list_begin(&(curr->descrs_t)); iter != list_end(&(curr->descrs_t)); iter = list_next(iter)) {
        struct descriptor* descript = list_entry(iter, struct descriptor, desc_elem);
        if (descript->fd - prev_num > 1) {
            return prev_num + 1;
        }
        prev_num = descript->fd;
    }
    return prev_num + 1;
}

int fd_to_file_for_remove(struct thread* curr, int fd)
{
    struct list_elem* iter;
    if (list_empty(&(curr->descrs_t))) {
        return NULL;
    }
    for (iter = list_begin(&(curr->descrs_t)); iter != list_end(&(curr->descrs_t)); iter = list_next(iter)) {
        struct descriptor* descript = list_entry(iter, struct descriptor, desc_elem);
        if (descript->fd == fd) {
            list_remove(iter);
            // 여기 주의
            if (descript->file != stdin_f && descript->file != stdout_f) {
                descript->file->refcnt--;
                if (descript->file->refcnt < 1)
                    file_close(descript->file);
            }
            free(descript);
            return true;
        }
    }
    return false;
}

struct file* fd_to_file_for_find(struct thread* curr, int fd)
{
    struct list_elem* iter;
    if (list_empty(&(curr->descrs_t))) {
        return NULL;
    }
    for (iter = list_begin(&(curr->descrs_t)); iter != list_end(&(curr->descrs_t)); iter = list_next(iter)) {
        struct descriptor* descript = list_entry(iter, struct descriptor, desc_elem);
        if (descript->fd == fd) {
            return descript->file;
        }
    }
    return NULL;
}

static void user_memory_access(const void* addr)
{
    if (addr == NULL || addr >= KERN_BASE) {
        thread_current()->exit_num = -1;
        thread_exit();
    }
}

static bool create(const char* file, unsigned initial_size)
{
    user_memory_access(file);
    lock_acquire(&filesys_lock);
    if (filesys_create(file, initial_size)) {
        lock_release(&filesys_lock);
        return TRUE;
    } else {
        lock_release(&filesys_lock);
        return FALSE;
    }
}

static void close(int fd)
{
    struct thread* curr = thread_current();
    fd_to_file_for_remove(curr, fd);
}

static int open(const char* file_name)
{
    struct file* file = NULL;
    struct thread* curr = thread_current();
    int fd;
    user_memory_access(file_name);
    lock_acquire(&filesys_lock);
    file = filesys_open(file_name);
    if (file == NULL) {
        lock_release(&filesys_lock);
        return -1;
    }
    fd = find_pos_fd_num(curr);
    if (fd == -1) {
        file_close(file);
        lock_release(&filesys_lock);
        return -1;
    }
    struct descriptor* descript = calloc(1, sizeof(struct descriptor));
    if (descript == NULL) {
        file_close(file);
        return -1;
    }
    descript->fd = fd;
    descript->file = file;
    descript->file->refcnt++;
    list_insert_ordered(&(curr->descrs_t), &(descript->desc_elem), cmp_fd_less, NULL);
    lock_release(&filesys_lock);
    return fd;
}

static int read(int fd, void* buffer, unsigned size)
{

    user_memory_access(buffer);
    if (fd < 0)
        return -1;

    struct thread* curr = thread_current();
    struct file* file = fd_to_file_for_find(curr, fd);

    if (file == NULL)
        return -1;
    if (file != stdin_f && file != stdout_f) {
        lock_acquire(&filesys_lock);
        int bytes = file_read(file, buffer, size);
        lock_release(&filesys_lock);
        return bytes;
    }
    if (file == stdin_f) {
        char* ptr = (char*)buffer;
        int bytes = 0;
        for (int i = 0; i < size; i++) {
            *ptr++ = input_getc();
            bytes++;
        }
        return bytes;
    }
    return -1;
}

static int write(int fd, void* buffer, unsigned size)
{
    user_memory_access(buffer);
    if (fd < 0)
        return -1;

    struct thread* curr = thread_current();
    struct file* file = fd_to_file_for_find(curr, fd);

    if (file == NULL)
        return -1;
    if (file != stdin_f && file != stdout_f) {
        if (file->deny_write)
            return 0;
        lock_acquire(&filesys_lock);
        int bytes = file_write(file, buffer, size);
        lock_release(&filesys_lock);
        return bytes;
    }

    if (file == stdout_f) {
        putbuf(buffer, size);
        return size;
    }

    return -1;
}

static void exec(const char* cmd_line)
{
    char* fn_copy;
    user_memory_access(cmd_line);
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL) {
        thread_current()->exit_num = -1;
        thread_exit();
    }
    strlcpy(fn_copy, cmd_line, PGSIZE);
    if (process_exec(fn_copy) == -1) {
        thread_current()->exit_num = -1;
        thread_exit();
    }
}

static void seek(int fd, off_t new_pos)
{
    struct file* file = fd_to_file_for_find(thread_current(), fd);
    if (fd < 0 || file == NULL || file == stdin_f || file == stdout_f) {
        return;
    } else
        file_seek(file, new_pos);
}

static tid_t fork(const char* thread_name, struct intr_frame* f)
{
    tid_t tid;
    user_memory_access(thread_name);
    return process_fork(thread_name, f);
}
static bool remove(const char* file)
{
    user_memory_access(file);
    return filesys_remove(file);
}

static int dup2(int oldfd, int newfd)
{
    struct thread* curr = thread_current();
    if (oldfd < 0 || newfd < 0)
        return -1;
    if (oldfd == newfd)
        return newfd;
    struct file* oldfile = fd_to_file_for_find(curr, oldfd);
    if (oldfile == NULL)
        return -1;
    struct file* target_file = fd_to_file_for_find(curr, newfd);
    if (target_file != NULL) {
        fd_to_file_for_remove(curr, newfd);
    }
    struct descriptor* new_descript = calloc(1, sizeof(struct descriptor));
    if (new_descript == NULL) {
        return -1;
    }
    new_descript->fd = newfd;
    new_descript->file = oldfile;
    new_descript->file->refcnt++;
    list_insert_ordered(&(curr->descrs_t), &(new_descript->desc_elem), cmp_fd_less, NULL);
    return newfd;
}

static unsigned int tell(int fd)
{
    struct thread* curr = thread_current();
    if (fd < 0) {
        return;
    }
    struct file* file = fd_to_file_for_find(curr, fd);
    if (file != stdin_f && file != stdout_f)
        return (file->pos);
    return -1;
}

/* The main system call interface */
void syscall_handler(struct intr_frame* f)
{
    // TODO: Your implementation goes here.
    int syscall_num = f->R.rax;
#ifdef VM
    thread_current()->rsp = f->rsp;
#endif
    size_t size;
    switch (syscall_num) {
    case SYS_HALT:
        power_off();
        break;
    case SYS_EXIT:
        f->R.rax = f->R.rdi;
        thread_current()->exit_num = (int)f->R.rdi;
        thread_exit();
        break;
    case SYS_FORK:
        f->R.rax = fork(f->R.rdi, f);
        break;
    case SYS_EXEC:
        exec(f->R.rdi);
        break;
    case SYS_WAIT:
        f->R.rax = process_wait(f->R.rdi);
        break;
    case SYS_CREATE:
        if (create((char*)f->R.rdi, (unsigned)f->R.rsi))
            f->R.rax = TRUE;
        else
            f->R.rax = FALSE;
        break;
    case SYS_REMOVE:
        f->R.rax = remove(f->R.rdi);
        break;
    case SYS_OPEN:
        f->R.rax = open(f->R.rdi);
        break;
    case SYS_FILESIZE:
        int fd = f->R.rdi;
        struct thread* curr = thread_current();
        if (fd < 2 || fd_to_file_for_find(curr, fd) == NULL) {
            f->R.rax = -1;
        } else {
            f->R.rax = (uint64_t)file_length(fd_to_file_for_find(curr, fd));
        }
        break;
    case SYS_READ:
        f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
        break;
    case SYS_SEEK:
        seek(f->R.rdi, f->R.rsi);
        break;
    case SYS_CLOSE:
        close(f->R.rdi);
        break;
    case SYS_WRITE:
        f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
        break;
    case SYS_DUP2:
        f->R.rax = dup2(f->R.rdi, f->R.rsi);
        break;
    case SYS_TELL:
        f->R.rax = tell(f->R.rdi);
        break;
    default:
        NOT_REACHED();
    }
}
