/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"


/* One semaphore in a list. */
struct semaphore_elem {
	struct list_elem elem;              /* List element. */
	struct semaphore semaphore;         /* This semaphore. */
};

/*우선순위 비교 용병 함수*/
static bool 
cmp_priority_more (const struct list_elem *a,
                     const struct list_elem *b,
                     void *aux UNUSED){
	struct thread *ta = list_entry (a, struct thread, elem);
    struct thread *tb = list_entry (b, struct thread, elem);
	return ta->priority > tb->priority;
}
//cond용, 인자로 전달되는 elem은 바로 스레드에 접근할수없다.
static bool 
cmp_sema_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
    struct semaphore_elem *sa = list_entry(a, struct semaphore_elem, elem);
    struct semaphore_elem *sb = list_entry(b, struct semaphore_elem, elem);

    struct list *waiters_a = &(sa->semaphore.waiters);
    struct list *waiters_b = &(sb->semaphore.waiters);

    struct thread *ta = list_entry(list_begin(waiters_a), struct thread, elem);
    struct thread *tb = list_entry(list_begin(waiters_b), struct thread, elem);

    return ta->priority > tb->priority;
}

//donation용, 인자로 전달되는 elem은 바로 스레드에 접근할수없다.
static bool 
cmp_done_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
	struct thread *ta = list_entry(a, struct thread, donation_elem);
	struct thread *tb = list_entry(b, struct thread, donation_elem);

	return ta->priority > tb->priority;
}

static void
kill_donor(struct lock *lock)
{
	struct list *donations = &(thread_current()->donation);
    struct list_elem *donor_elem; 
    struct thread *donor_thread;

    if (list_empty(donations))
        return;

    donor_elem = list_front(donations);

    while (1)
    {
        donor_thread = list_entry(donor_elem, struct thread, donation_elem);
        if (donor_thread->lock_on_wait == lock)
            list_remove(&donor_thread->donation_elem);
        donor_elem = list_next(donor_elem);
        if (donor_elem == list_end(donations))
            return;
    }
}

/* 세마포어 SEMA를 VALUE 값으로 초기화함 세마포어는 음이 아닌 정수 값이 이를
	조작하기 위한 두가지 원자적 연산으로 구성함:

   - down or "P": 값이 양수가 될 때까지 기다렸다가 값을 1 감소시킴

   - up or "V": 값을 1 증가시킴 (그리고 만약 기다리는 스레드가 있다면 그중 하나를 깨움) */
void
sema_init (struct semaphore *sema, unsigned value) {
	ASSERT (sema != NULL);

	sema->value = value;
	list_init (&sema->waiters);
}

/* 	Down or "P" 세마포어에 대한 Down 또는 P 연산
	SEMA의 값이 양수가 될 때까지 기다린 다음, 원자적으로 값을 1 감소시킴
	
	이 함수는 잠들 수 있으므로, 인터럽트 핸들러 내부에서 호출되어서는 안됨!!!!
	이 함수는 인터럽트가 비활성화 된 상태에서 호출될 수 있지만,
	만약 잠들게 되면 다음 스케줄될 스레드가 아마도
	인터럽트를 다시 켤 것임....*/
void
sema_down (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);
	ASSERT (!intr_context ());

	old_level = intr_disable ();
	while (sema->value == 0) {
		//project 1-2 우선순위 순으로 넣기
		list_insert_ordered(&sema->waiters, &thread_current ()->elem, cmp_priority_more, NULL);
		thread_block ();
	}
	sema->value--;
	intr_set_level (old_level);
}

/* 	Down or "P" operation on a semaphore, 
	하지만 세마포어가 이미 0이 아닐 경우에만 시도함
	세마포어 값이 감소되면 true를, 그렇지 않으면 false를 반환함

   이 함수는 잠들지 않기 때문에 인터럽트 핸들러 내에서 호출될 수 있슴당 */
bool
sema_try_down (struct semaphore *sema) {
	enum intr_level old_level;
	bool success;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level (old_level);

	return success;
}

/* 	Up or "V" 연산 for 세마포어. SEMA의 값을 증가시키고 SEMA를 기다리는 스레드가 있다면
	그중 하나를 깨움

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (!list_empty (&sema->waiters))
	{
		list_sort(&sema->waiters, cmp_priority_more, NULL);
		thread_unblock (list_entry(list_pop_front (&sema->waiters),struct thread, elem));
	}
	sema->value++;
	thread_preempted();
	intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) {
	struct semaphore sema[2];
	int i;

	printf ("Testing semaphores...");
	sema_init (&sema[0], 0);
	sema_init (&sema[1], 0);
	thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up (&sema[0]);
		sema_down (&sema[1]);
	}
	printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) {
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down (&sema[0]);
		sema_up (&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock) {
	ASSERT (lock != NULL);

	lock->holder = NULL;
	sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (!lock_held_by_current_thread (lock));

	//project1-3 donation
	struct thread *curr = thread_current();
	if (lock -> holder != NULL)
	{
		curr->lock_on_wait = lock;
		list_insert_ordered(&(lock->holder->donation), &(curr->donation_elem), cmp_done_priority, NULL);
		donation_priority ();
	}
	sema_down (&lock->semaphore);
	//획득했으니까 풀어줌
	curr->lock_on_wait = NULL;
	lock->holder = thread_current ();
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock) {
	bool success;

	ASSERT (lock != NULL);
	ASSERT (!lock_held_by_current_thread (lock));

	success = sema_try_down (&lock->semaphore);
	if (success)
		lock->holder = thread_current ();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (lock_held_by_current_thread (lock));
	
	kill_donor(lock);
	retrieve_priority ();

	lock->holder = NULL;
	sema_up (&lock->semaphore);
}


/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) {
	ASSERT (lock != NULL);

	return lock->holder == thread_current ();
}



/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond) {
	ASSERT (cond != NULL);

	list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) {
	struct semaphore_elem waiter;

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	sema_init (&waiter.semaphore, 0);
	// project1-2-> 뒤에다 넣지말고 잘 넣기
	list_insert_ordered(&cond->waiters, &waiter.elem, cmp_sema_priority, NULL);
	lock_release (lock);
	sema_down (&waiter.semaphore);
	lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	if (!list_empty (&cond->waiters))
	{
		list_sort(&cond->waiters, cmp_sema_priority, NULL);
		sema_up (&list_entry (list_pop_front (&cond->waiters),
					struct semaphore_elem, elem)->semaphore);
	}
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);

	while (!list_empty (&cond->waiters))
		cond_signal (cond, lock);
}

void
donation_priority (void)
{
	struct thread *curr = thread_current();
	struct thread *holder;

	int priority = curr->priority;
	for (int i = 0; i < 8; i++)
	{
		if (curr->lock_on_wait == NULL)
			return;
		holder = curr->lock_on_wait->holder;
		holder->priority = priority;
		curr = holder;
	}
}

void
retrieve_priority (void)
{
	struct thread *curr = thread_current();
	struct list *donations = &(thread_current()->donation);
	struct thread *donations_front;

	if (list_empty(donations))
	{
		curr->priority = curr->actual_priority;
		return;
	}
	donations_front = list_entry(list_front(donations), struct thread, donation_elem);
	curr->priority = donations_front->priority;
}