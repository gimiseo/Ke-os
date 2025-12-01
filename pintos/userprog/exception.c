#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "intrinsic.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill(struct intr_frame*);
static void page_fault(struct intr_frame*);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void exception_init(void)
{
    /* These exceptions can be raised explicitly by a user program,
       e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
       we set DPL==3, meaning that user programs are allowed to
       invoke them via these instructions. */
    intr_register_int(3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
    intr_register_int(4, 3, INTR_ON, kill, "#OF Overflow Exception");
    intr_register_int(5, 3, INTR_ON, kill, "#BR BOUND Range Exceeded Exception");

    /* These exceptions have DPL==0, preventing user processes from
       invoking them via the INT instruction.  They can still be
       caused indirectly, e.g. #DE can be caused by dividing by
       0.  */
    intr_register_int(0, 0, INTR_ON, kill, "#DE Divide Error");
    intr_register_int(1, 0, INTR_ON, kill, "#DB Debug Exception");
    intr_register_int(6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
    intr_register_int(7, 0, INTR_ON, kill, "#NM Device Not Available Exception");
    intr_register_int(11, 0, INTR_ON, kill, "#NP Segment Not Present");
    intr_register_int(12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
    intr_register_int(13, 0, INTR_ON, kill, "#GP General Protection Exception");
    intr_register_int(16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
    intr_register_int(19, 0, INTR_ON, kill, "#XF SIMD Floating-Point Exception");

    /* Most exceptions can be handled with interrupts turned on.
       We need to disable interrupts for page faults because the
       fault address is stored in CR2 and needs to be preserved. */
    intr_register_int(14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void exception_print_stats(void)
{
    printf("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void kill(struct intr_frame* f)
{
    /* This interrupt is one (probably) caused by a user process.
       For example, the process might have tried to access unmapped
       virtual memory (a page fault).  For now, we simply kill the
       user process.  Later, we'll want to handle page faults in
       the kernel.  Real Unix-like operating systems pass most
       exceptions back to the process via signals, but we don't
       implement them. */

    /* The interrupt frame's code segment value tells us where the
       exception originated. */
    switch (f->cs) {
    case SEL_UCSEG:
        /* User's code segment, so it's a user exception, as we
           expected.  Kill the user process.  */
        printf("%s: dying due to interrupt %#04llx (%s).\n", thread_name(), f->vec_no, intr_name(f->vec_no));
        intr_dump_frame(f);
        thread_exit();

    case SEL_KCSEG:
        /* Kernel's code segment, which indicates a kernel bug.
           Kernel code shouldn't throw exceptions.  (Page faults
           may cause kernel exceptions--but they shouldn't arrive
           here.)  Panic the kernel to make the point.  */
        intr_dump_frame(f);
        PANIC("Kernel bug - unexpected interrupt in kernel");

    default:
        /* Some other code segment?  Shouldn't happen.  Panic the
           kernel. */
        printf("Interrupt %#04llx (%s) in unknown segment %04x\n", f->vec_no, intr_name(f->vec_no), f->cs);
        thread_exit();
    }
}

/* 페이지 폴트 핸들러입니다. 이것은 가상 메모리를 구현하기 위해 반드시 채워져야 하는
   뼈대(skeleton) 코드입니다. 프로젝트 2의 일부 해결 방법에서도 이 코드를 수정해야
   할 수 있습니다.

   진입 시, 폴트를 일으킨 주소는 CR2(제어 레지스터 2)에 저장되어 있으며,
   폴트에 대한 정보는 exception.h의 PF_* 매크로에 설명된 형식으로
   F의 error_code 멤버에 들어있습니다.

   여기 있는 예제 코드는 그 정보를 파싱하는 방법을 보여줍니다.

   이 두 가지에 대한 더 많은 정보는 [IA32-v3a] 섹션 5.15
   "Exception and Interrupt Reference"의 "Interrupt 14--Page Fault Exception (#PF)"
   설명에서 찾을 수 있습니다. */
static void page_fault(struct intr_frame* f)
{
    bool not_present; /* True: 존재하지 않는 페이지(not-present), False: 읽기 전용(r/o) 페이지에 쓰기 시도. */
    bool write;       /* True: 쓰기(write) 접근, False: 읽기(read) 접근. */
    bool user;        /* True: 유저(user)에 의한 접근, False: 커널(kernel)에 의한 접근. */
    void* fault_addr; /* 폴트가 발생한 주소. */
                      /* 폴트를 유발한 접근 대상 가상 주소인 '폴팅 주소(faulting address)'를 획득합니다.
                             이것은 코드일 수도 있고 데이터일 수도 있습니다.
                             이것은 폴트를 일으킨 명령어의 주소(그건 f->rip임)와 반드시 일치하지는 않습니다. */

    fault_addr = (void*)rcr2();

    /* 인터럽트를 다시 켭니다 (CR2 값이 변경되기 전에 확실히 읽어오기 위해
           잠시 꺼뒀던 것뿐입니다). */
    intr_enable();

    /* Determine cause. */
    not_present = (f->error_code & PF_P) == 0;
    write = (f->error_code & PF_W) != 0;
    user = (f->error_code & PF_U) != 0;

#ifdef VM
    /* For project 3 and later. */
    if (vm_try_handle_fault(f, fault_addr, user, write, not_present))
        return;
#endif

	/* 시스템 콜 처리 중(Kernel Context)에 유저 주소(User Vaddr)에 접근하다가 
       Page Fault가 났는데, 위에서 처리가 안 됐다면(Lazy Loading 아님) 
       이는 유저가 잘못된 포인터를 넘긴 명백한 Bad Pointer 상황입니다.
       이때는 에러 메시지를 출력하지 말고 조용히 프로세스를 종료해야 테스트를 통과합니다. */
       
    if (!user && is_user_vaddr(fault_addr)) {
        thread_current()->exit_num = -1;
        thread_exit();
    }
    /* Count page faults. */
    page_fault_cnt++;

    /* If the fault is true fault, show info and exit. */
    printf("Page fault at %p: %s error %s page in %s context.\n", fault_addr,
           not_present ? "not present" : "rights violation", write ? "writing" : "reading", user ? "user" : "kernel");
    thread_current()->exit_num = -1;
    thread_exit();
    // kill (f);
}
