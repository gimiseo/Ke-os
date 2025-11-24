#ifndef THREADS_INIT_H
#define THREADS_INIT_H

#include <debug.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "filesys/file.h"

/* An open file. */
struct file {
	struct inode *inode;        /* File's inode. */
	off_t pos;                  /* Current position. */
	bool deny_write;            /* Has file_deny_write() been called? */
};

/* Physical memory size, in 4 kB pages. */
extern size_t ram_pages;

/* Page map level 4 with kernel mappings only. */
extern uint64_t *base_pml4;

/* -q: Power off when kernel tasks complete? */
extern bool power_off_when_done;

extern struct file *stdin_f;
extern struct file *stdout_f;

void power_off (void) NO_RETURN;

#endif /* threads/init.h */
