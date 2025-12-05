#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "filesys/file.h"
#ifdef VM
#include "vm/vm.h"
#endif
// #ifndef USERPROG
// #define USERPROG
// #endif

/* States in a thread's life cycle. */
enum thread_status {
    THREAD_RUNNING, /* Running thread. */
    THREAD_READY,   /* Not running but ready to run. */
    THREAD_BLOCKED, /* Waiting for an event to trigger. */
    THREAD_DYING    /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) - 1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0      /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63     /* Highest priority. */
/*project 1-4 advanced*/
#define NICE_MAX 20
#define NICE_DEFAULT 0
#define NICE_MIN -20
#define RECENT_CPU_DEFAULT 0
#define LOAD_AVG_DEFAULT 0
/*project 2 advanced*/
#define FILE_MAX 128

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
    /* Owned by thread.c. */
    tid_t tid;                 /* Thread identifier. */
    enum thread_status status; /* Thread state. */
    char name[16];             /* Name (for debugging purposes). */
    int priority;              /* Priority. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem; /* List element. */

    /* Project 1 - Alarm Clock */
    int64_t wake_time;

    /* Project 1-3 - donation */
    int actual_priority;            /*donation 종료시 기존 priority로 돌아오기용*/
    struct lock* lock_on_wait;      /*스레드가 요청했지만 다른 스레드가 점유하고 있어서 기다리는 lock*/
    struct list donation;           /*priority 기부 리스트 - 기부받기 전으로 되돌리기 용*/
    struct list_elem donation_elem; /*이 스레드가 기부하면 들어가는 요소*/

    /*project 1-4 - advenced*/
    int nice;
    int recent_cpu;
    /*~~project 2*/
#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint64_t* pml4; /* Page map level 4 */
    /*project 2 추가*/
    int exit_num;
    struct list descrs_t; /*디스크립터 분리*/
    struct intr_frame parent_if;
    struct thread* parent;            /*부모*/
    struct list childs;               /*자식 리스트*/
    struct list_elem child_elem;      /*자식 요소*/
    struct semaphore wait;            /*wait용 세마*/
    struct semaphore load;            /*자식 로드 세마*/
    struct semaphore waiting_parents; /*부모의 신호를 기다리는 세마*/
    struct file* exec_file;           /*실행파일*/
#endif
#ifdef VM
    /* Table for whole virtual memory owned by thread. */
    struct supplemental_page_table spt;
    uintptr_t rsp;
#endif

    /* Owned by thread.c. */
    struct intr_frame tf; /* Information for switching */
    unsigned magic;       /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void* aux);
tid_t thread_create(const char* name, int priority, thread_func*, void*);

void thread_block(void);
void thread_unblock(struct thread*);

/*project 1-2 선점함수*/
void thread_preempted(void);

/* Project 1 - Alarm Clock */
void thread_sleep(int64_t tick);
void thread_awake(int64_t ticks);
/* ~Alarm Clock */

struct thread* thread_current(void);
tid_t thread_tid(void);
const char* thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

/*project 1 -> Advanced scheduler*/
void cal_priority(struct thread* t);
void cal_recent_cpu(struct thread* t);
void cal_load_avg(void);
void update_priority(void);
void incr_recent_cpu(void);
void update_recent_cpu(void);

void do_iret(struct intr_frame* tf);

#endif /* threads/thread.h */
